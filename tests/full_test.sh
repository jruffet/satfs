#!/bin/bash

# Return 0 if all tests passed
keep_vagrant=false
[ "$1" == "--keep-vagrant" ] && keep_vagrant=true

cd $(dirname $0)

if [ $keep_vagrant == false ]; then
    cd vagrant
    vagrant up
    cd ..
fi

# Run pytest locally + testinfra on vagrant for full test + remote tests "local to the vagrant box"
echo "[+] local pytest"
pytest -v && \
cd vagrant && \
echo "[+] remote pytest" && \
vagrant ssh -c "sudo pytest /vagrant/tests/vagrant/remote/ -v --noconftest -p no:cacheprovider --forked" && \
echo "[+] testinfra" && \
pytest -v --hosts=vagrant-satfs --ssh-config=<(vagrant ssh-config)

status=$?

if [ $keep_vagrant == false ]; then
    vagrant destroy -f
fi

exit $status
