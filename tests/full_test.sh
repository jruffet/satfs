#!/bin/bash
BOX_PREFIX="satfs-debian"

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
for version in bookworm64 testing64; do
    box_name="${BOX_PREFIX}-${version}" && \
    echo "[+] remote pytest ($box_name)" && \
    vagrant ssh $box_name -c "sudo pytest /vagrant/tests/vagrant/remote/ -v --noconftest -p no:cacheprovider --forked" && \
    echo "[+] testinfra ($box_name)" && \
    pytest -v --hosts=$box_name --ssh-config=<(vagrant ssh-config $box_name)
done

status=$?

if [ $keep_vagrant == false ]; then
    vagrant destroy -f
fi

exit $status
