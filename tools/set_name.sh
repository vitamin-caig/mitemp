mac=${1}
name=${2}
encoded_name=$(echo -n "${name}" | xxd -ps)
handle=0x03
gatttool -b ${mac} --char-write-req -a ${handle} -n ${encoded_name} && \
gatttool -b ${mac} --char-read -a ${handle} | cut -f2 -d: | xxd -r -ps
echo
