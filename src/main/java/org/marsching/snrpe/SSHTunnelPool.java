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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

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

    private ConcurrentHashMap<SSHSessionKey, SSHSessionInfo> tunnelForHost = new ConcurrentHashMap<SSHSessionKey, SSHSessionInfo>();
    private JSch jsch;
    private SNRPEConfiguration configuration;

    private class SSHSessionInfo {
        public Session sshSession;
        public Map<SSHPortForwardingKey, Integer> localPortForPortForwarding = new HashMap<SSHTunnelPool.SSHPortForwardingKey, Integer>();
    }

    private class SSHSessionKey {
        private String user;
        private String host;
        private int port;

        public SSHSessionKey(String host, int port, String user) {
            super();
            this.host = host;
            this.port = port;
            this.user = user;
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(19, 23).append(host).append(port)
                    .append(user).toHashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj != null && obj instanceof SSHSessionKey) {
                SSHSessionKey other = (SSHSessionKey) obj;
                return new EqualsBuilder().append(this.host, other.host)
                        .append(this.port, other.port)
                        .append(this.user, other.user).isEquals();
            } else {
                return false;
            }
        }

        @Override
        public String toString() {
            return new StringBuilder().append(user).append("@").append(host)
                    .append(":").append(port).toString();
        }
    }

    private class SSHPortForwardingKey {
        private String targetHost;
        private int targetPort;

        public SSHPortForwardingKey(String targetHost, int targetPort) {
            super();
            this.targetHost = targetHost;
            this.targetPort = targetPort;
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(47, 31).append(targetHost)
                    .append(targetPort).toHashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj != null && obj instanceof SSHPortForwardingKey) {
                SSHPortForwardingKey other = (SSHPortForwardingKey) obj;
                return new EqualsBuilder()
                        .append(this.targetHost, other.targetHost)
                        .append(this.targetPort, other.targetPort).isEquals();
            } else {
                return false;
            }
        }

        @Override
        public String toString() {
            return new StringBuilder().append(targetHost).append(":")
                    .append(targetPort).toString();
        }
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
     * @param sshHost
     *            name of the host to connect to. This can be a DNS name or an
     *            IP address.
     * @param sshPort
     *            port number the SSH daemon is listening on. If
     *            <code>null</code>, the port specified in the configuration
     *            file is used.
     * @param sshUser
     *            username for the SSH connection. If <code>null</code>, the
     *            username specified in the configuration file is used.
     * @param targetHost
     *            the target host for the port forwarding (this name is resolved
     *            by the SSH daemon on the target side of the tunnel. If
     *            <code>null</code> the hostname specified in the configuration
     *            file is used.
     * @param targetPort
     *            the target port for the port forwarding. If <code>null</code>
     *            the port specified in the configuration file is used.
     * 
     * @return port number that locally exposes the remote service or a negative
     *         number, if the connection could not be established.
     */
    public int getLocalPortForHost(String sshHost, Integer sshPort,
            String sshUser, String targetHost, Integer targetPort) {
        Validate.notNull(sshHost, "The SSH host must not be null.");
        Validate.isTrue(sshPort == null || (sshPort > 0 && sshPort < 65536),
                "The SSH port must be between 1 and 65535.");
        Validate.isTrue(targetPort == null
                || (targetPort > 0 && targetPort < 65536),
                "The target port must be between 1 and 65535.");
        if (sshUser == null) {
            sshUser = configuration.getSSHUser(sshHost);
        }
        if (sshPort == null) {
            sshPort = configuration.getSSHPort(sshHost);
        }
        SSHSessionKey sessionKey = new SSHSessionKey(sshHost, sshPort, sshUser);
        SSHSessionInfo sessionInfo = tunnelForHost.get(sshHost);
        if (sessionInfo == null) {
            sessionInfo = new SSHSessionInfo();
            SSHSessionInfo existingTunnel = tunnelForHost.putIfAbsent(
                    sessionKey, sessionInfo);
            if (existingTunnel != null) {
                sessionInfo = existingTunnel;
            }
        }
        synchronized (sessionInfo) {
            Session session = sessionInfo.sshSession;
            if (session == null || !session.isConnected()) {
                sessionInfo.sshSession = null;
                sessionInfo.localPortForPortForwarding.clear();
                session = createSession(sshHost, sshPort, sshUser);
            }
            if (session != null) {
                if (targetHost == null) {
                    targetHost = configuration
                            .getSSHPortForwardingTargetHost(sshHost);
                }
                if (targetPort == null) {
                    targetPort = configuration
                            .getSSHPortForwardingTargetPort(sshHost);
                }
                SSHPortForwardingKey pfKey = new SSHPortForwardingKey(
                        targetHost, targetPort);
                Integer localPort = sessionInfo.localPortForPortForwarding
                        .get(pfKey);
                if (localPort != null && localPort >= 0) {
                    return localPort;
                } else {
                    localPort = createPortForwarding(session, targetHost,
                            targetPort);
                    if (localPort != null && localPort >= 0) {
                        sessionInfo.localPortForPortForwarding.put(pfKey,
                                localPort);
                        return localPort;
                    } else {
                        return -1;
                    }
                }
            } else {
                return -1;
            }
        }
    }

    private Session createSession(String hostname, int port, String username) {
        Session session;
        try {
            session = this.jsch.getSession(username, hostname, port);
            session.setConfig("StrictHostKeyChecking",
                    configuration.getSSHStrictHostKeyChecking() ? "yes" : "no");
            session.setServerAliveInterval(10000);
            session.setServerAliveCountMax(5);
            String password = configuration.getSSHPassword(hostname);
            if (password != null) {
                session.setPassword(password);
            }
            session.connect(configuration.getSSHConnectTimeout());
            return session;
        } catch (JSchException e) {
            System.err
                    .println("Error while trying to create SSH session for \""
                            + username + "@" + hostname + "\": "
                            + e.getMessage());
            return null;
        }
    }

    private int createPortForwarding(Session session, String targetHost,
            int targetPort) {
        int localPort;
        try {
            localPort = session.setPortForwardingL(0, targetHost, targetPort);
            return localPort;
        } catch (JSchException e) {
            System.err
                    .println("Error while trying to create port-forwarding for \""
                            + session.getUserName()
                            + "@"
                            + session.getHost()
                            + "\" and target address \""
                            + targetHost
                            + ":"
                            + targetPort + "\": " + e.getMessage());
            return -1;
        }
    }

}
