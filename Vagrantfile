# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.define "sdn" do |sdn|
    sdn.vm.box = "bento/ubuntu-20.04"
    sdn.vm.network :private_network, ip: "172.0.0.20"
    sdn.vm.provision "shell", inline: <<-SHELL
      sudo apt update
      sudo apt -y install git python3-pip xauth
      git clone https://github.com/mininet/mininet
      sudo mininet/util/install.sh -a
      git clone https://github.com/osrg/ryu.git
      pip3 install ./ryu
      # curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -
      # echo "source $HOME/.poetry/env" >> /etc/profile
    SHELL
  end

  # NOTE(ahill): Uncomment this if you wish to use 'xterm' functionality in mininet
  config.ssh.forward_x11 = true
  config.ssh.forward_agent = true

  config.vm.provider "virtualbox" do |v|
    v.customize ["modifyvm", :id, "--memory", "1024"]
  end
end