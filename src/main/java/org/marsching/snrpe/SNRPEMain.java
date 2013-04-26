/*
 * Copyright 2013 Sebastian Marsching
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.marsching.snrpe;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.Parser;
import org.apache.commons.configuration.ConfigurationException;

/**
 * Main class for SNRPE service. This service listens on a port (4673 by
 * default) and waits for request to create an SSH tunnel to the NRPE service on
 * target systems. It keeps track of the tunnels that have been created, in
 * order to use only a single SSH connection per target host.
 * 
 * @author Sebastian Marsching
 */
public class SNRPEMain {

    private File configurationFile;
    private SNRPEConfiguration configuration;
    private SSHTunnelPool tunnelPool;

    /**
     * Runs the SNRPE service.
     * 
     * @param args
     *            command-line parameters.
     */
    public static void main(String[] args) {
        try {
            (new SNRPEMain()).run(args);
        } catch (AbortExecutionException e) {
            System.exit(e.getExitCode());
        }
    }

    private void run(String[] args) throws AbortExecutionException {
        // Parse command-line parameters.
        parseCommandLine(args);

        // Load configuration file.
        loadConfiguration();

        // Initialize the pool for the SSH connections.
        tunnelPool = new SSHTunnelPool(configuration);

        // Listen on server socket.
        InetAddress bindAddress;
        try {
            bindAddress = InetAddress.getByName(configuration.getBindAddress());
        } catch (UnknownHostException e) {
            System.err.println("Could resolve bind address \""
                    + configuration.getBindAddress() + "\": " + e.getMessage());
            throw new AbortExecutionException(1);
        }
        int bindPort = configuration.getBindPort();
        ThreadPoolExecutor requestHandlerExecutor = new ThreadPoolExecutor(5,
                Integer.MAX_VALUE, 10, TimeUnit.SECONDS,
                new SynchronousQueue<Runnable>(),
                new ThreadPoolExecutor.CallerRunsPolicy());
        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(bindPort, 10, bindAddress);
        } catch (IOException e) {
            System.err.println("Could not bind to server socket on "
                    + bindAddress.getHostAddress() + ":" + bindPort + ": "
                    + e.getMessage());
            throw new AbortExecutionException(1);
        }
        // In the current implementation, there is no method for requesting the
        // server to stop, however we might add this in the future.
        boolean stopRequested = false;
        try {
            while (stopRequested == false) {
                Socket sessionSocket;
                try {
                    sessionSocket = serverSocket.accept();
                } catch (IOException e) {
                    System.err
                            .println("Eror while waiting for a connection on "
                                    + bindAddress.getHostAddress() + ":"
                                    + bindPort + ": " + e.getMessage());
                    throw new AbortExecutionException(2);
                }
                requestHandlerExecutor
                        .execute(new RequestHandler(sessionSocket));
            }
        } finally {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // Ignore error on socket close operation.
            }
        }
    }

    private void parseCommandLine(String[] args) throws AbortExecutionException {
        Options options = new Options();
        options.addOption("c", "configuration-file", true,
                "Path to the configuration file (default is \"/etc/snrpe/snrpe.conf\")");
        options.addOption("h", "help", false,
                "Shows this informational message");
        Parser parser = new GnuParser();
        CommandLine commandLine;
        try {
            commandLine = parser.parse(options, args, true);
        } catch (ParseException e) {
            printHelp(options);
            throw new AbortExecutionException(1);
        }
        if (commandLine.hasOption("h")) {
            printHelp(options);
            throw new AbortExecutionException(0);
        }
        if (commandLine.hasOption("c")) {
            configurationFile = new File(commandLine.getOptionValue("c"));
        } else {
            configurationFile = new File("/etc/snrpe/snrpe.conf");
        }
    }

    private void loadConfiguration() throws AbortExecutionException {
        try {
            configuration = new SNRPEConfiguration(configurationFile);
        } catch (ConfigurationException e) {
            System.err
                    .println("Error while trying to load configuration from file \""
                            + configurationFile.getPath()
                            + "\": "
                            + e.getMessage());
            throw new AbortExecutionException(1);
        }
    }

    private void printHelp(Options options) {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp("java " + this.getClass().getName(), options);
    }

    private class RequestHandler implements Runnable {
        private Socket socket;

        public RequestHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                        socket.getOutputStream(), "UTF-8"));
                String requestLine = reader.readLine();
                String[] lineParts = requestLine.split("\\s+");
                String sshHost = null;
                Integer sshPort = null;
                String sshUser = null;
                String targetHost = null;
                Integer targetPort = null;
                boolean foundIllegalParameters = false;
                if (requestLine.trim().isEmpty()) {
                    foundIllegalParameters = true;
                }
                if (lineParts.length < 1 || lineParts.length > 5) {
                    foundIllegalParameters = true;
                }
                for (int i = 0; i < lineParts.length; i++) {
                    if (lineParts[i].equals(":")) {
                        lineParts[i] = null;
                    }
                }
                if (lineParts.length >= 1) {
                    sshHost = lineParts[0];
                    if (sshHost == null) {
                        foundIllegalParameters = true;
                    }
                }
                if (lineParts.length >= 2 && lineParts[1] != null) {
                    try {
                        sshPort = Integer.parseInt(lineParts[1]);
                    } catch (NumberFormatException e) {
                        foundIllegalParameters = true;
                    }
                    if (sshPort != null && (sshPort < 1 || sshPort > 65535)) {
                        foundIllegalParameters = true;
                    }
                }
                if (lineParts.length >= 3) {
                    sshUser = lineParts[2];
                }
                if (lineParts.length >= 4) {
                    targetHost = lineParts[3];
                }
                if (lineParts.length >= 5 && lineParts[4] != null) {
                    try {
                        targetPort = Integer.parseInt(lineParts[4]);
                    } catch (NumberFormatException e) {
                        foundIllegalParameters = true;
                    }
                    if (targetPort < 1 || targetPort > 65535) {
                        foundIllegalParameters = true;
                    }
                }
                int localPort;
                if (!foundIllegalParameters) {
                    localPort = tunnelPool.getLocalPortForHost(sshHost,
                            sshPort, sshUser, targetHost, targetPort);
                } else {
                    localPort = -2;
                }
                writer.println(localPort);
                writer.flush();
            } catch (IOException e) {
                System.err.println("I/O error while handling connection from "
                        + socket.getInetAddress().getHostAddress() + ":"
                        + socket.getPort() + ": " + e.getMessage());
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    // Ignore error on socket close operation.
                }
                socket = null;
            }
        }
    }

    private class AbortExecutionException extends Exception {
        private static final long serialVersionUID = -4375320176615243261L;

        private int exitCode;

        public AbortExecutionException(int exitCode) {
            this.exitCode = exitCode;
        }

        public int getExitCode() {
            return exitCode;
        }
    }

}
