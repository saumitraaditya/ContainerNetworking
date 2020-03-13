# ContainerNetworking
contains IPOP CNI plugin based on Bridge plugin.
Plugin will create a veth pair, one end of veth insided container namespace other in host.
sets the veth interface inside container as default gateway  
configure the container veth interface with IP address from IPAM plugin
check if IPoP bridge exists , if it does attach the host end of veth pair to the bridge.
path: ./plugins/plugins/main/ipop/ipopCNI.go
