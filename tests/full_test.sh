#!/bin/bash
set -euo pipefail

BOX_PREFIX="satfs-"

keep_vagrant=false
return_code=1

cleanup() {
    if [ $keep_vagrant == false ]; then
        vagrant destroy -f
    fi
    exit $return_code
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

box_names=$(vagrant status --machine-readable | grep ',state,' | cut -d',' -f2)
for box_name in $box_names; do
    echo "[+] remote pytest ($box_name)"
    vagrant ssh $box_name -c "sudo pytest /vagrant/tests/vagrant/remote/ -v --noconftest -p no:cacheprovider --forked"
    echo "[+] testinfra ($box_name)"
    pytest -v --hosts=$box_name --ssh-config=<(vagrant ssh-config $box_name)
done

return_code=0
