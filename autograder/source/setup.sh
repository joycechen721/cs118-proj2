apt-get update
apt-get install -y libssl-dev netcat

make -C /autograder/source/reference

# Keep only server and client binaries, not source
mv /autograder/source/reference /autograder/source/reference-orig
mkdir -p /autograder/source/reference
mv /autograder/source/reference-orig/server /autograder/source/reference-orig/client /autograder/source/reference/
rm -rf /autograder/source/reference-orig