from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Controller

class SimpleTopo(Topo):
    def build(self):
        # Add a switch
        switch = self.addSwitch('s1')

        # Add two hosts
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')

        # Connect hosts to the switch
        self.addLink(host1, switch)
        self.addLink(host2, switch)

# Create and start the network
topo = SimpleTopo()

# Specify the ONOS controller IP and port (default ONOS port is 6633)
net = Mininet(topo=topo, controller=Controller, build=False)
controller = net.addController('c0', controller=Controller, ip='127.0.0.1', port=6633)
net.start()

# Ping all the hosts to verify connectivity
net.pingAll()

# Stop the network
net.stop()
