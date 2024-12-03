#! /usr/bin/env nix-shell
#! nix-shell -i bash -p bash
mkdir -p .ansible/collections/ansible_collections/cloudera/cluster
git archive $(git rev-parse --abbrev-ref HEAD) | tar -x -C .ansible/collections/ansible_collections/cloudera/cluster
(cd .ansible/collections/ansible_collections/cloudera/cluster && pytest)

