# Check if Golang is installed
if ! go version >/dev/null 2>/dev/null; then
  echo "Golang is not installed" >&2
  exit 1
fi

checkGolangVersion()
{
#least Edition v1.10.1
E1=1
E2=10
E3=1
echo Need golang version is : $E1.$E2.$E3

V1=`go version 2>&1|awk '{print $3}'|awk -F '.' '{print $1}'|awk -F, '{print substr($1,length($1)-0)}'`
V2=`go version 2>&1|awk '{print $3}'|awk -F '.' '{print $2}'`
V3=`go version 2>&1|awk '{print $3}'|awk -F '.' '{print $3}'`

if [ $V1 -lt $E1 ];then
        echo 'Please update to golang version 1.10 or higher!'
        exit 1
    elif [ $V1 -eq $E1 ];then     
        if [ $V2 -lt $E2 ];then 
            echo 'Please update to golang version 1.10 or higher!'
            exit 1
        elif [ $V2 -eq $E2 ];then
            if [ $V3 -lt $E3 ];then 
                echo 'Please update to golang version 1.10 or higher!'
                exit 1
            fi
        fi    
    fi

    echo Your golang version is OK!
}
checkGolangVersion
