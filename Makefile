all:
	$(MAKE) baseAMI bastionAMI vaultAMI

baseAMI:
	cd hawl1 && packer build packer.json

bastionAMI:
	cd bastion && packer build packer.json

vaultAMI:
	cd vault && packer build packer.json

installOSX:
	brew install packer jq

