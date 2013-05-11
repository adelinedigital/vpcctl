#!/usr/bin/env python

import subprocess
import sys
import os

SSHKEYGEN = '/usr/bin/ssh-keygen'
BUCKET0 = 'pvt-bucket'

def main(alias):
    command = (SSHKEYGEN, '-q', '-t', 'rsa', '-b', '2048', '-f', '/dev/shm/' + alias + '-rsa', '-C', 'root@'+alias, '-P', '')
    subprocess.call(command)
    command = (SSHKEYGEN, '-q', '-t', 'dsa', '-b', '1024', '-f', '/dev/shm/' + alias + '-dsa', '-C', 'root@'+alias, '-P', '')
    subprocess.call(command)

    print '#cloud-config'
    print

    print 'timezone: US/Pacific'
    print

    print 'packages:'
    print ' - salt-minion'
    print

    print 'ssh_keys:'
    print '  dsa_private: |'
    with open('/dev/shm/' + alias + '-dsa', 'r') as fd:
        for line in fd.readlines():
            print '    ' + line.strip()
    print
    print '  dsa_public:'
    with open('/dev/shm/' + alias + '-dsa.pub', 'r') as fd:
        print '    ',
        print fd.read()
    print
    print '  rsa_private: |'
    with open('/dev/shm/' + alias + '-rsa', 'r') as fd:
        for line in fd.readlines():
            print '    ' + line.strip()
    print
    print '  rsa_public:'
    with open('/dev/shm/' + alias + '-rsa.pub', 'r') as fd:
        print '    ',
        print fd.read()
    print
    print 'runcmd:'
    print ' - [ mkdir, -p, /etc/salt ]'
    print ' - [ /usr/bin/python, -c, "import boto;boto.connect_s3().get_bucket(\'' + BUCKET0 + '\').get_key(\'minion\').get_contents_to_filename(\'/etc/salt/minion\')" ]'
    print ' - [ /sbin/service, salt-minion, restart ]'

    os.remove('/dev/shm/' + alias + '-dsa')
    os.remove('/dev/shm/' + alias + '-rsa')
    os.remove('/dev/shm/' + alias + '-dsa.pub')
    os.remove('/dev/shm/' + alias + '-rsa.pub')

if __name__ == '__main__':
    main(sys.argv[1])
