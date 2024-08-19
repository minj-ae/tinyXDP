#!/bin/bash

ip_to_hex() {
    printf "%08x" $(echo $1 | awk -F. '{printf "%d", $1*256*256*256+$2*256*256+$3*256+$4}')
}

mask_to_prefix() {
    local mask=$1
    local length=0
    for octet in $(echo $mask | tr '.' ' '); do
        case $octet in
            255) length=$((length+8));;
            254) length=$((length+7)); break;;
            252) length=$((length+6)); break;;
            248) length=$((length+5)); break;;
            240) length=$((length+4)); break;;
            224) length=$((length+3)); break;;
            192) length=$((length+2)); break;;
            128) length=$((length+1)); break;;
            0) break;;
        esac
    done
    echo $length
}
