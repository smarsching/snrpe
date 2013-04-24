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
import java.util.List;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.commons.configuration.plist.PropertyListConfiguration;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * Configuration for the SNRPE service.
 * 
 * @author Sebastian Marsching
 */
public class SNRPEConfiguration {

    private final static String DEFAULT_SSH_KNOWN_HOSTS_FILE = getDefaultSSHKnownHostsFile();
    private final static String DEFAULT_SSH_KEY_FILE = getDefaultSSHKeyFile();

    private PropertyListConfiguration configuration;

    /**
     * Creates a configuration that is based on a configuration file. The
     * configuration file is parsed by an instance of
     * {@link PropertyListConfiguration}.
     * 
     * @param configurationFile
     *            file that stores the configuration
     * @throws ConfigurationException
     *             if the configuration file cannot be parsed.
     */
    public SNRPEConfiguration(File configurationFile)
            throws ConfigurationException {
        configuration = new PropertyListConfiguration();
        configuration.setEncoding("UTF-8");
        configuration.load(configurationFile);
    }

    /**
     * Returns the IP address or hostname the service will listen on. Default is
     * to "127.0.0.1".
     * 
     * @return IP address or hostname the service listens on.
     */
    public String getBindAddress() {
        return configuration.getString("bindAddress", "127.0.0.1");
    }

    /**
     * Returns the TCP port number the service will listen on. Default is 4673.
     * 
     * @return port number the service listens on.
     */
    public int getBindPort() {
        return configuration.getInt("bindPort", 4673);
    }

    private SubnodeConfiguration getHostConfiguration(String hostname) {
        ConfigurationNode root = configuration.getRootNode();
        ConfigurationNode hosts = getFirstChildNode(root, "hosts");
        if (hosts != null) {
            ConfigurationNode host = getFirstChildNode(hosts, hostname);
            if (host != null) {
                String key = getNodeKey(host);
                return configuration.configurationAt(key);
            }
        }
        return null;
    }

    private String getNodeKey(ConfigurationNode node) {
        ConfigurationNode parentNode = node.getParentNode();
        String parentKey;
        if (parentNode != null) {
            parentKey = getNodeKey(parentNode);
        } else {
            parentKey = null;
        }
        return configuration.getExpressionEngine().nodeKey(node, parentKey);
    }

    /**
     * Returns the path to the SSH known-hosts file. Default is
     * "$HOME/.ssh/known_hosts". This file is only used if strict host-key
     * checking is enabled.
     * 
     * @return Path to the the SSH known-hosts file.
     * @see #getSSHStrictHostKeyChecking()
     */
    public String getSSHKnownHostsFile() {
        return configuration.getString("ssh.knownHostsFile",
                DEFAULT_SSH_KNOWN_HOSTS_FILE);
    }

    /**
     * Returns <code>true</code> if strict host-key checking is enabled. If
     * strict host-key checking is enabled, a connection to an SSH host is only
     * established if the public key sent by the host is included in the
     * known-hosts file, using the specified hostname. If strict host-key
     * checking is disabled, the host key is not checked. Default is
     * <code>false</code>.
     * 
     * @return <code>true</code> if strict host-key checking is enabled,
     *         <code>false</code> otherwise.
     */
    public boolean getSSHStrictHostKeyChecking() {
        return configuration.getBoolean("ssh.strictHostKeyChecking", false);
    }

    /**
     * Returns the time to wait for an SSH connection to be established in
     * milliseconds. Default is 30000 ms.
     * 
     * @return time to wait for an SSH connection to be established in
     *         milliseconds.
     */
    public int getSSHConnectTimeout() {
        return configuration.getInt("ssh.connectTimeout", 30000);
    }

    /**
     * Returns the path to the SSH private-key-file that is used for
     * authentication. Only SSHv2 RSA and DSA keys are supported. Default is
     * "$HOME/.ssh/id_rsa".
     * 
     * @return path the SSH privat-key file.
     */
    public String getSSHKeyFile() {
        return configuration.getString("ssh.keyFile", DEFAULT_SSH_KEY_FILE);
    }

    /**
     * Returns the SSH username for the specified host. Default is "root".
     * 
     * @param hostname
     *            name of the host the configuration option is supposed to be
     *            retrieved for.
     * @return username to be used for SSH connection.
     */
    public String getSSHUser(String hostname) {
        SubnodeConfiguration hostConfiguration = getHostConfiguration(hostname);
        if (hostConfiguration != null) {
            return hostConfiguration.getString("user", getSSHUser());
        } else {
            return getSSHUser();
        }
    }

    private String getSSHUser() {
        return configuration.getString("ssh.user", "root");
    }

    /**
     * Returns the SSH password for the specified host. Default is
     * <code>null</code>.
     * 
     * @param hostname
     *            name of the host the configuration option is supposed to be
     *            retrieved for.
     * @return password to be used for SSH connection or <code>null</code> if no
     *         password is set.
     */
    public String getSSHPassword(String hostname) {
        SubnodeConfiguration hostConfiguration = getHostConfiguration(hostname);
        if (hostConfiguration != null) {
            return hostConfiguration.getString("password", getSSHPassword());
        } else {
            return getSSHPassword();
        }
    }

    private String getSSHPassword() {
        return configuration.getString("ssh.password", null);
    }

    /**
     * Returns the name of the host to connect to. This can be used to connect
     * to a different host than the actual target host (e.g. because the actual
     * target host cannot be accessed directly). If no target host is configured
     * explicitly, the passed <code>hostname</code> is returned.
     * 
     * @param hostname
     *            name of the host the configuration option is supposed to be
     *            retrieved for.
     * @return DNS name or IP address of the host the SSH connection is supposed
     *         to be established with.
     * @see #getSSHPortForwardingTargetHost()
     */
    public String getSSHHost(String hostname) {
        SubnodeConfiguration hostConfiguration = getHostConfiguration(hostname);
        String sshHost = null;
        if (hostConfiguration != null) {
            sshHost = hostConfiguration.getString("host", null);
        }
        if (sshHost != null) {
            return sshHost;
        }
        sshHost = getSSHHost();
        if (sshHost != null) {
            return sshHost;
        }
        return hostname;
    }

    private String getSSHHost() {
        return configuration.getString("ssh.host", null);
    }

    /**
     * Returns the TCP port number the SSH service is expected to be running on.
     * Default is 22.
     * 
     * @param hostname
     *            name of the host the configuration option is supposed to be
     *            retrieved for.
     * @return port number the SSH service is running on.
     */
    public int getSSHPort(String hostname) {
        SubnodeConfiguration hostConfiguration = getHostConfiguration(hostname);
        if (hostConfiguration != null) {
            return hostConfiguration.getInt("port", getSSHPort());
        } else {
            return getSSHPort();
        }

    }

    private int getSSHPort() {
        return configuration.getInt("ssh.port", 22);
    }

    /**
     * Returns the name of the host that the SSH host shall forward the TCP
     * connection to. This can be used to establish the SSH connection with one
     * host, but actually connect to the NRPE service running on a different
     * host (e.g. because the actual target host cannot be accessed directly).
     * Default is "localhost" (the NRPE service is running on the same host as
     * the SSH service).
     * 
     * @param hostname
     *            name of the host the configuration option is supposed to be
     *            retrieved for.
     * @return DNS name or IP address of the host the SSH connection is supposed
     *         to be established with.
     * @see #getSSHHost(String)
     */
    public String getSSHPortForwardingTargetHost(String hostname) {
        SubnodeConfiguration hostConfiguration = getHostConfiguration(hostname);
        if (hostConfiguration != null) {
            return hostConfiguration.getString("portForwardingTargetHost",
                    getSSHPortForwardingTargetHost());
        } else {
            return getSSHPortForwardingTargetHost();
        }
    }

    private String getSSHPortForwardingTargetHost() {
        return configuration.getString("ssh.portForwardingTargetHost",
                "localhost");
    }

    /**
     * Returns the TCP port number the NRPE service is expected to be running
     * on. The port-forwarding will be established with this port. Default is
     * 5666.
     * 
     * @param hostname
     *            name of the host the configuration option is supposed to be
     *            retrieved for.
     * @return port number the NRPE service is running on.
     */
    public int getSSHPortForwardingTargetPort(String hostname) {
        SubnodeConfiguration hostConfiguration = getHostConfiguration(hostname);
        if (hostConfiguration != null) {
            return hostConfiguration.getInt("portForwardingTargetPort",
                    getSSHPortForwardingTargetPort());
        } else {
            return getSSHPortForwardingTargetPort();
        }

    }

    private int getSSHPortForwardingTargetPort() {
        return configuration.getInt("ssh.portForwardingTargetPort", 5666);
    }

    private static String getDefaultSSHKnownHostsFile() {
        return getHomeDirectory() + File.separator + ".ssh" + File.separator
                + "known_hosts";
    }

    private static String getDefaultSSHKeyFile() {
        return getHomeDirectory() + File.separator + ".ssh" + File.separator
                + "id_rsa";
    }

    private static String getHomeDirectory() {
        String homeDirectory = System.getProperty("user.home");
        if (homeDirectory == null) {
            if (File.separatorChar == '\\') {
                return "C:";
            } else {
                return "";
            }
        }
        return homeDirectory;
    }

    private static ConfigurationNode getFirstChildNode(
            ConfigurationNode parent, String name) {
        List<ConfigurationNode> nodes = parent.getChildren(name);
        if (nodes.size() > 0) {
            return nodes.get(0);
        } else {
            return null;
        }
    }

}
