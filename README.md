# Contiki-NG: The OS for Next Generation IoT Devices

Contiki-NG is an open-source, cross-platform operating system for Next-Generation IoT devices. It focuses on dependable (secure and reliable) low-power communication and standard protocols, such as IPv6/6LoWPAN, 6TiSCH, RPL, and CoAP. Contiki-NG comes with extensive documentation, tutorials, a roadmap, release cycle, and well-defined development flow for smooth integration of community contributions.

Contiki-NG started as a fork of the Contiki OS and retains some of its original features.
* GitHub repository: https://github.com/contiki-ng/contiki-ng
* Documentation: https://github.com/contiki-ng/contiki-ng/wiki

## Alan's instructions for SYSC5500 project
Requirements: git latest, cooja latest, docker latest

### Host:
	git clone git@github.com:flowac/iot-ssl.git contiki-ng
	cd contiki-ng
	git submodule update --init --recursive
	docker pull contiker/contiki-ng

### Host (save to ~/.bashrc):
	export CNG_PATH=<absolute-path-to-your-contiki-ng>
	alias contiker="docker run --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 --mount type=bind,source=$CNG_PATH,destination=/home/user/contiki-ng -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v /dev/bus/usb:/dev/bus/usb -ti contiker/contiki-ng"

### Docker: (Call this alias on the host to enter docker: contiker)
	sudo apt install lsb-release libssl-dev
	cd tools/cooja
	./gradlew run

### Host (saving docker state):
	docker ps
	docker commit <container-id> newcon
	alias newcon="docker run --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 --mount type=bind,source=$CNG_PATH,destination=/home/user/contiki-ng -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v /dev/bus/usb:/dev/bus/usb -ti newcon"

### Host (running saved container):
	newcon
