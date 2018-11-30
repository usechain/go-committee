#!/bin/bash
# prepare test configuration files
# zhangliang@usechain.net
# 2018.11.29
#
OS="LINUX"
LinuxConfigDir="${HOME}/.usechain/committee"
OSXConfigDir=${HOME}/Library/usechain/committee
WindowsConfigDir=${HOME}/AppData/Roaming/usechain/committee
ConfigDir="$LinuxConfigDir"

case "$OSTYPE" in
  solaris*) OS="SOLARIS" ;;
  linux*)   OS="LINUX" ;;
  bsd*)     OS="BSD" ;;
  darwin*)  OS="OSX" ; ConfigDir=$OSXConfigDir;; # Mac
  msys*)    OS="WINDOWS" ; ConfigDir=$WindowsConfigDir;;# Git Bash/msysGit
  cygwin*)  OS="WINDOWS" ; ConfigDir=$WindowsConfigDir;; # Cygwin
  *)        OS="UNKNOWN"; echo "unknown: $OSTYPE" ;;
esac

KeystoreDir=$ConfigDir/keystore

echo
echo "OS:$OS"
echo "Usechain ConfigDir: $ConfigDir"
if [ ${OS}x == "UNKNOWN"x ]; then
    echo "error OS $OSTYPE not supported, exit ..."
    exit;
fi

cur_dir=$(cd `dirname $0`; pwd)
echo
echo $cur_dir

# make config directory for user
if [ ! -d $ConfigDir ]; then
    echo "mkdir $ConfigDir"
    mkdir -p $ConfigDir
fi

# make directory for keystore
if [ ! -d $KeystoreDir ]; then
    echo "mkdir $KeystoreDir"
    mkdir -p $KeystoreDir
fi

echo "prepare configure files...."

authctr=$ConfigDir/identityContract.json
if [ ! -f "$authctr" ]; then
    cp  $cur_dir/profile/identityContract.json $ConfigDir/.
fi

cmt=$ConfigDir/committee.json
if [ ! -f "$cmt" ]; then
    cp  $cur_dir/profile/committee.json $ConfigDir/.
fi

ctr=$ConfigDir/managerContract.json
if [ ! -f "$ctr" ]; then
    cp  $cur_dir/profile/managerContract.json $ConfigDir/.
fi

usedinfo=$ConfigDir/used.json
if [ ! -f "$usedinfo" ]; then
    cp  $cur_dir/profile/used.json $ConfigDir/.
fi

whisperinfo=$ConfigDir/whisper.json
if [ ! -f "$whisperinfo" ]; then
    cp  $cur_dir/profile/whisper.json $ConfigDir/.
fi

cd $ConfigDir

echo "ls $ConfigDir:"
ls $ConfigDir

