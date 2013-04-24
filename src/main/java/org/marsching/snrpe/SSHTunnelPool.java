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

import java.io.File;
import java.util.concurrent.ConcurrentHashMap;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

/**
 * Pool for SSH tunnels. The pool will open an SSH connection and create a port
 * forwarding the first time a connection is requested for a host. When another
 * connection for the same host is requested later, the existing connection is
 * reused.
 * 
 * @author Sebastian Marsching
 */
public class SSHTunnelPool {

    private ConcurrentHashMap<String, SSHTunnel> tunnelForHost = new ConcurrentHashMap<String, SSHTunnel>();
    private JSch jsch;
    private SNRPEConfiguration configuration;

    private class SSHTunnel {
        public Session sshSession;
        public int localForwardedPort;
    }

    /**
     * Create a pool that used the specified configuration.
     * 
     * @param configuration
     *            configuration that is used for creating the SSH tunnels.
     */
    public SSHTunnelPool(SNRPEConfiguration configuration) {
        this.configuration = configuration;
        this.jsch = new JSch();
        try {
            this.jsch.setKnownHosts(configuration.getSSHKnownHostsFile());
        } catch (JSchException e) {
            System.err
                    .println("Error while trying to set known-hosts file to \""
                            + configuration.getSSHKnownHostsFile() + "\": "
                            + e.getMessage());
        }
        File keyFile = new File(configuration.getSSHKeyFile());
        if (keyFile.exists()) {
            try {
                this.jsch.addIdentity(keyFile.getAbsolutePath());
            } catch (JSchException e) {
                System.err.println("Error while trying to add identity \""
                        + keyFile.getPath() + "\": " + e.getMessage());
            }
        }
    }

    /**
     * Returns the local TCP port that exposes the remote service running on the
     * specified port. If no port-forwarding exists yet for this host, a new
     * connection is created. A negative number is returned, if no
     * port-forwarding exists and no new port-forwarding could be created.
     * 
     * @param hostname
     *            name of the host to connect to. This can be a DNS name or an
     *            IP address.
     * @return port number that locally exposes the remote service or a negative
     *         number, if the connection could not be established.
     */
    public int getLocalPortForHost(String hostname) {
        SSHTunnel tunnel = tunnelForHost.get(hostname);
        if (tunnel == null) {
            tunnel = new SSHTunnel();
            SSHTunnel existingTunnel = tunnelForHost.putIfAbsent(hostname,
                    tunnel);
            if (existingTunnel != null) {
                tunnel = existingTunnel;
            }
        }
        synchronized (tunnel) {
            Session session = tunnel.sshSession;
            if (session == null || !session.isConnected()) {
                createSession(hostname, tunnel);
                if (tunnel.sshSession != null
                        && tunnel.sshSession.isConnected()) {
                    return tunnel.localForwardedPort;
                } else {
                    return -1;
                }
            } else {
                return tunnel.localForwardedPort;
            }
        }
    }

    private void createSession(String hostname, SSHTunnel tunnel) {
        tunnel.sshSession = null;
        tunnel.localForwardedPort = -1;
        Session session;
        try {
            session = this.jsch.getSession(configuration.getSSHUser(hostname),
                    configuration.getSSHHost(hostname),
                    configuration.getSSHPort(hostname));
            session.setConfig("StrictHostKeyChecking",
                    configuration.getSSHStrictHostKeyChecking() ? "yes" : "no");
            session.setServerAliveInterval(10000);
            session.setServerAliveCountMax(5);
            String password = configuration.getSSHPassword(hostname);
            if (password != null) {
                session.setPassword(password);
            }
            session.connect(configuration.getSSHConnectTimeout());
        } catch (JSchException e) {
            System.err
                    .println("Error while trying to create SSH session for host \""
                            + hostname + "\": " + e.getMessage());
            return;
        }
        int localPort;
        try {
            localPort = session.setPortForwardingL(0,
                    configuration.getSSHPortForwardingTargetHost(hostname),
                    configuration.getSSHPortForwardingTargetPort(hostname));
        } catch (JSchException e) {
            System.err
                    .println("Error while trying to create port-forwarding for SSH host + \""
                            + hostname
                            + "\" and target address \""
                            + configuration
                                    .getSSHPortForwardingTargetHost(hostname)
                            + ":"
                            + configuration
                                    .getSSHPortForwardingTargetPort(hostname)
                            + "\": " + e.getMessage());
            return;
        }
        tunnel.sshSession = session;
        tunnel.localForwardedPort = localPort;
    }

}
