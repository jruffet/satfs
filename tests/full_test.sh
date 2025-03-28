#!/bin/bash
set -euo pipefail

BOX_PREFIX="satfs-debian"
keep_vagrant=false

cleanup() {
    if [ $keep_vagrant == false ]; then
        vagrant destroy -f
    fi
    exit 1
}
trap 'cleanup' EXIT

### Start ###
cd $(dirname $0)
[ "${1:-}" == "--keep-vagrant" ] && keep_vagrant=true

if [ $keep_vagrant == false ]; then
    cd vagrant
    vagrant up
    cd ..
fi

echo "[+] local pytest"
pytest -v

cd vagrant

for version in bookworm64 testing64; do
    box_name="${BOX_PREFIX}-${version}"
    echo "[+] remote pytest ($box_name)"
    vagrant ssh $box_name -c "sudo pytest /vagrant/tests/vagrant/remote/ -v --noconftest -p no:cacheprovider --forked"
    echo "[+] testinfra ($box_name)"
    pytest -v --hosts=$box_name --ssh-config=<(vagrant ssh-config $box_name)
done

# Reached only if no test failed
exit 0
