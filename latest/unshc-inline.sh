#!/bin/bash
VERSION="1.0"

OBJDUMP=`which objdump`
GREP=`which grep`
CUT=`which cut`
SHRED=`which shred`
UNIQ=`which uniq`
SORT=`which sort`
GCC=`which gcc`
WC=`which wc`
AWK=`which awk`
SED=`which sed`
TR=`which tr`
HEAD=`which head`
TAIL=`which tail`
PRINTF=`which printf`

BINARY=""
TMPBINARY=$(mktemp /tmp/XXXXXX)
DUMPFILE=""
STRINGFILE=""
DUMPFUNC=$(mktemp /tmp/XXXXXX)
MOVLABLEFILE=$(mktemp /tmp/XXXXXX)
CALLADDRFILE=$(mktemp /tmp/XXXXXX)
CALLSIZEFILE=$(mktemp /tmp/XXXXXX)

declare -A LISTOFCALL

# Simple usage help / man
function usage(){
        printf "[*] Usage : $0 [OPTIONS] <file.sh.x>\n"
        printf "\t -h | --help                          : print this help message\n"
        printf "\t -d DUMPFILE | --dumpfile DUMPFILE    : provide an object dump file (objdump -D script.sh.x > DUMPFILE)\n"
        printf "\t -s STRFILE | --stringfile STRFILE    : provide a string dump file (objdump -s script.sh.x > STRFILE)\n"
        printf "\t -o OUTFILE | --outputfile OUTFILE    : indicate the output file name\n\n"
        printf "[*] e.g : \n"
        printf "\t$0 script.sh.x\n"
        printf "\t$0 script.sh.x -o script_decrypted.sh\n"
        printf "\t$0 script.sh.x -d /tmp/dumpfile -s /tmp/strfile\n"
        printf "\t$0 script.sh.x -a 400f9b -d /tmp/dumpfile -s /tmp/strfile -o script_decrypted.sh\n"
}

# Clean all temp file created for this script
function clean(){
        $SHRED -zu -n 1 $DUMPFILE $DUMPFUNC $CALLADDRFILE $CALLSIZEFILE $STRINGFILE $MOVLABLEFILE $TMPBINARY ${TMPBINARY}.c >/dev/null 2>&1
}

# Clean error exit function after cleaning temp file
function exit_error(){
        clean
        exit 1;
}

# Check the availability of basic commands usefull for this script
function check_binaries() {
        if [ ! -x ${OBJDUMP} ]; then
                echo "[-] Error, cannot execute or find objdump binary"
                exit_error
        fi
        if [ ! -x ${GREP} ]; then
                echo "[-] Error, cannot execute or find grep binary"
                exit_error
        fi
        if [ ! -x ${CUT} ]; then
                echo "[-] Error, cannot execute or find cut binary"
                exit_error
        fi
        if [ ! -x ${SHRED} ]; then
                echo "[-] Error, cannot execute or find shred binary"
                exit_error
        fi
        if [ ! -x ${UNIQ} ]; then
                echo "[-] Error, cannot execute or find uniq binary"
                exit_error
        fi
        if [ ! -x ${SORT} ]; then
                echo "[-] Error, cannot execute or find sort binary"
                exit_error
        fi
        if [ ! -x ${GCC} ]; then
                echo "[-] Error, cannot execute or find gcc binary"
                exit_error
        fi
        if [ ! -x ${WC} ]; then
                echo "[-] Error, cannot execute or find wc binary"
                exit_error
        fi
}

# Create dump files of encrypted script
function generate_dump() {
        # DUMPFILE dump to retrive arc4 address, address and size of each arc4 arguments and pwd
        $OBJDUMP -b "binary" -m "i386:x86-64" -D $BINARY > "$DUMPFILE"
        # STRINGFILE dump to retrieve pwd and arc4 argument
        $OBJDUMP -b "binary" -m "i386:x86-64" -s $BINARY > "$STRINGFILE"
}

function extract_decrypt_func() {
    # extract the addr that reference the sys_execve
    EXECVE_ADDR=$($GREP -B 1 "syscall" $DUMPFILE | $GREP "mov.*0x3b,%eax" | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+")
    # echo $EXECVE_ADDR
    # extract the addr that reference the execvp

    BEFOR_LINE=25
    while([ $BEFOR_LINE -le 37 ]); do
        EXECVP_ADDR=$($GREP -B ${BEFOR_LINE} -m 1 "call.*0x${EXECVE_ADDR}" $DUMPFILE | $GREP -B 1 "jmp" | $GREP "mov.*0x.*,%.*" | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+")
        # echo $EXECVP_ADDR
        BEFOR_LINE=$(($BEFOR_LINE+3))

        if [[ ! -z "$EXECVP_ADDR" ]]; then
            break
        fi

        if [[ $BEFOR_LINE > 31 ]]; then
            echo "[-] Unable to extract addresses of exevp..."
            return 1
        fi
    done

    # echo $EXECVP_ADDR
    CALL_EXECVP_ADDR=$($GREP "call.*0x${EXECVP_ADDR}" $DUMPFILE | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+")
    # echo $CALL_EXECVP_ADDR
    echo "[+] Extract to the address that call the execvp : [0x$CALL_EXECVP_ADDR]"
    # extract the function
    CALL_EXECVP_LINE=$($GREP -n "${CALL_EXECVP_ADDR}:" $DUMPFILE | $GREP ": *${CALL_EXECVP_ADDR}" | $CUT -d ":" -f 1 | $GREP -Eo "[0-9]+")
    # echo $CALL_EXECVP_LINE
    # extract the end of function

    MIN_LINE=1
    for ((i = $(($CALL_EXECVP_LINE-1)); i > 0; i--)); do
        LABLE=$($SED -n "${i}p" $DUMPFILE | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+")
        # echo $LABLE
        CALL_STR=$($GREP -m 1 "call.*${LABLE}$" $DUMPFILE | $GREP "0x${LABLE}")
        # echo $CALL_STR
        if [ ! -z "$CALL_STR" ]; then
            # echo $CALL_STR
            MIN_LINE=$(($i))
            # echo $MIN_LINE
            echo "[+] Extract to the decryption function start address \"${LABLE}\" line number \"${MIN_LINE}\""
            break
        fi
    done

    MAX_LINE=$($WC -l $DUMPFILE | $CUT -d " " -f 1 | $GREP -Eo "[0-9]+")
    DUMPFILE_LINE=$MAX_LINE
    for ((i = $(($CALL_EXECVP_LINE+1)); i <= $(($DUMPFILE_LINE)); i++)); do
        LABLE=$($SED -n "${i}p" $DUMPFILE | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+")
        # echo $LABLE
        CALL_STR=$($GREP -m 1 "call.*${LABLE}$" $DUMPFILE | $GREP "0x${LABLE}")
        # echo $CALL_STR
        if [ ! -z "$CALL_STR" ]; then
            # echo $CALL_STR
            MAX_LINE=$(($i - 1))
            # echo $MAX_LINE
            echo "[+] Extract to the decryption function end address \"${LABLE}\" line number \"${MAX_LINE}\""
            break
        fi
    done

    $SED -n "${MIN_LINE},${MAX_LINE}p" $DUMPFILE > $DUMPFUNC

    if [[ $MIN_LINE -le 1 ]]; then
        echo "[-] Unable to extract the decryption function..."
        return 1
    else
        return 0
    fi
}

function extract_data_from_binary() {
    # echo $1
    # echo $2
    KEY=$1
    # Like the other NLINES
    NLINES=$(( ($2 / 16) +2 ))
    # Like the other LASTBYTE
    LASTBYTE="0x${KEY:$((${#KEY}-1))}"
    # Extract PWD from STRINGFILE
    STRING=$( $GREP -A $(($NLINES-1)) -E "^ ${KEY:1:$((${#KEY}-2))}0 " $STRINGFILE | $AWK '{ print $2$3$4$5}' | $TR '\n' 'T' | $SED -e "s:T::g")
    STRING=${STRING:$((2*$LASTBYTE))}
    STRING=${STRING:0:$(($2 * 2))}
    # Encode / rewrite PWD in the \x??\x?? format
    FINALSTRING=""
    for ((i=0;i<$((${#STRING} /2 ));i++)); do
            FINALSTRING="${FINALSTRING}\x${STRING:$(($i * 2)):2}"
    done
    # echo $FINALSTRING
}

function extract_password_from_binary() {
    KEY_ADDR=$($GREP -Eo "add.*0x[0-9a-f]+.*,%dil" $DUMPFUNC | $GREP -Eo "0x[0-9a-f]+" | $CUT -d "x" -f 2 | $GREP -Eo "[0-9a-f]+")
    KEY_SIZE=$($GREP -A 5 -E "add.*0x[0-9a-f]+.*,%dil" $DUMPFUNC | $GREP -Eo "cmp.*0x[0-9a-f]+" | $GREP -Eo "0x[0-9a-f]+")
    # KEY_SIZE=0x100
    echo -e "\t[+] PWD address found : [0x$KEY_ADDR]"
    echo -e "\t[+] PWD size found : [$KEY_SIZE]"

    extract_data_from_binary $KEY_ADDR $KEY_SIZE
    VAR_PSWD=$FINALSTRING
}

function extract_variable_1() {
    echo -e "\t[+] Working with var address at offset 0x[$1]"
    VARADDR=$1
    case "$j" in
    0)  NBYTES=0x41
        extract_data_from_binary $VARADDR $NBYTES
        VAR_MSG1=$FINALSTRING
        VAR_MSG1_Z=$NBYTES;;
    1)  NBYTES=0x1
        extract_data_from_binary $VARADDR $NBYTES
        VAR_DATE=$FINALSTRING
        VAR_DATE_Z=$NBYTES;;
    2)  NBYTES=0xf
        extract_data_from_binary $VARADDR $NBYTES
        VAR_XECC=$FINALSTRING
        VAR_XECC_Z=$NBYTES;;
    3)  NBYTES=0x16
        extract_data_from_binary $VARADDR $NBYTES
        VAR_TST1=$FINALSTRING
        VAR_TST1_Z=$NBYTES;;
    4)  NBYTES=0x16
        extract_data_from_binary $VARADDR $NBYTES
        VAR_CHK1=$FINALSTRING
        VAR_CHK1_Z=$NBYTES;;
    5)  NBYTES=0x13
        extract_data_from_binary $VARADDR $NBYTES
        VAR_MSG2=$FINALSTRING
        VAR_MSG2_Z=$NBYTES;;
   esac
   j=$(($j + 1))
}

function extract_variable_2() {
    echo -e "\t[+] Working with var address at offset [0x$1]"
    VARADDR=$1
    case "$j" in
    0)  NBYTES=0x1
        extract_data_from_binary $VARADDR $NBYTES
        VAR_DATE=$FINALSTRING
        VAR_DATE_Z=$NBYTES;;
    1)  NBYTES=0xa
        extract_data_from_binary $VARADDR $NBYTES
        VAR_SHLL=$FINALSTRING
        VAR_SHLL_Z=$NBYTES;;
    11)  NBYTES=0x3
        extract_data_from_binary $VARADDR $NBYTES
        VAR_INLO=$FINALSTRING
        VAR_INLO_Z=$NBYTES;;
    14)  NBYTES=0x1
        extract_data_from_binary $VARADDR $NBYTES
        VAR_LSTO=$FINALSTRING
        VAR_LSTO_Z=$NBYTES;;
    15)  NBYTES=0x1
        extract_data_from_binary $VARADDR $NBYTES
        VAR_RLAX=$FINALSTRING
        VAR_RLAX_Z=$NBYTES;;
    5)  NBYTES=0x1
        extract_data_from_binary $VARADDR $NBYTES
        VAR_OPTS=$FINALSTRING
        VAR_OPTS_Z=$NBYTES;;
   esac
   j=$(($j + 1))
}

function extract_variables_from_dumpfunc() {
    # extract do...while loop
    $GREP -E "mov .*0x[0-9a-f]{6,}," $DUMPFUNC | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+" > $MOVLABLEFILE

    VARIABLES=""

    IFS=$'\n' read -d '' -r -a MOVLABLE < $MOVLABLEFILE
    for (( x = 0; x < ${#MOVLABLE[*]}; x = x+1 ))
    do
        i=${MOVLABLE[$x]}
        CMPPOS=$($GREP -A 15 -E " +${i}:" $DUMPFUNC | $GREP -A 3 "xor" | $GREP "cmp")

        if [[ ! -z "$CMPPOS" ]]; then
            MOVCOUNT=$($GREP -A 2 -E " +${i}:" $DUMPFUNC | $GREP "mov " | $WC -l)
            if [ $MOVCOUNT -eq 1 ]; then
                VARADDR=$($GREP -E " +${i}:" $DUMPFUNC | $GREP -Eo "0x[0-9a-f]+,"| $GREP -Eo "0x[0-9a-f]+" | $CUT -d "x" -f 2 | $GREP -Eo "[0-9a-f]+")
                
                VARIABLES=`echo -e "$VARIABLES$VARADDR,"`
            fi
        fi
    done

    OLD_IFS="$IFS"
    IFS=","
    ARRAY=($VARIABLES)
    IFS="$OLD_IFS"
    ARRAYLEN=${#ARRAY[@]}

    if [ $ARRAYLEN -lt 6 ]; then
        echo "[-] Unable to extract variables..."
        return 1
    fi

    j=0
    for (( x = 0; x < 6; x = x+1 ))
    do
        VARADDR=${ARRAY[$x]}
        extract_variable_1 $VARADDR
    done

    # extract variables by xor
    VARIABLES=$($GREP -E "xor +%[a-z]{2},0x[0-9,a-f]{6,}.*# 0x[0-9,a-f]{6,}" $DUMPFUNC | $GREP -Eo "# 0x[0-9,a-f]{6,}$" | $GREP -Eo "0x[0-9a-f]+" | $CUT -d "x" -f 2 | $GREP -Eo "[0-9a-f]+")
    VARIABLES=`echo $VARIABLES`
    # echo $VARIABLES
    # echo $VARIABLES | hexdump -C
    OLD_IFS="$IFS"
    IFS=" "
    ARRAY=($VARIABLES)
    IFS="$OLD_IFS"
    ARRAYLEN=${#ARRAY[@]}

    if [ $ARRAYLEN -lt 17 ]; then
        echo "[-] Unable to extract variables..."
        return 1
    fi

    j=0
    for (( x = 0; x < 17; x = x+1 ))
    do
        VARADDR=${ARRAY[$x]}
        extract_variable_2 $VARADDR
    done

    # extract text
    $GREP -E "mov .*0x[0-9,a-f]{6,},%\w+$" $DUMPFUNC | $CUT -d ":" -f 1 | $GREP -Eo "[0-9a-f]+" > $MOVLABLEFILE
    
    TEXT=""

    IFS=$'\n' read -d '' -r -a MOVLABLE < $MOVLABLEFILE
    for (( x = 0; x < ${#MOVLABLE[*]}; x = x+1 ))
    do
        i=${MOVLABLE[$x]}
        MOVZBLPOS=$($GREP -A 2 -E " +${i}" $DUMPFUNC | $GREP -A 1 "movzbl" | $SED -n "2p" | $GREP -A 1 "movzbl")

        if [[ ! -z "$MOVZBLPOS" ]]; then
            TEXTADDR=$($GREP -E " +${i}:" $DUMPFUNC | $GREP -E "0x[0-9,a-f]{6,}" | $GREP -Eo "0x[0-9a-f]+" | $CUT -d "x" -f 2 | $GREP -Eo "[0-9a-f]+")
            # echo $TEXTADDR
            TEXTENDADDR=$($GREP -m 1 -A 30 -E " +${i}:" $DUMPFUNC | $GREP "cmp" | $GREP -E "0x[0-9,a-f]{6,}" | $GREP -Eo "0x[0-9a-f]+" | $CUT -d "x" -f 2 | $GREP -Eo "[0-9a-f]+")
            # echo $TEXTENDADDR

            VARADDR=$TEXTADDR
            NBYTES=$(("0x"$TEXTENDADDR-"0x"$TEXTADDR))
            NBYTES="0x$($PRINTF "%x" $NBYTES)"
            echo -e "\t[+] TEXT address found : [0x$VARADDR]"
            echo -e "\t[+] TEXT size found : [$NBYTES)]"
            extract_data_from_binary $VARADDR $NBYTES
            VAR_TEXT=$FINALSTRING
            VAR_TEXT_Z=$NBYTES
            break
        fi
    done

    if [ -z "$VAR_TEXT" ]; then
        echo "[-] Unable to extract TEXT..."
        return 1
    fi

    return 0
}

# This function append a generic engine for decrypt from shc project. With out own new variables extracted.
# Rather than execute the source code decrypted, it's printed in stdout.
function generic_file(){
cat > ${TMPBINARY}.c << EOF
#define msg1_z $VAR_MSG1_Z
#define date_z $VAR_DATE_Z
#define shll_z $VAR_SHLL_Z
#define inlo_z $VAR_INLO_Z
#define xecc_z $VAR_XECC_Z
#define lsto_z $VAR_LSTO_Z
#define tst1_z $VAR_TST1_Z
#define chk1_z $VAR_CHK1_Z
#define msg2_z $VAR_MSG2_Z
#define rlax_z $VAR_RLAX_Z
#define opts_z $VAR_OPTS_Z
#define text_z $VAR_TEXT_Z
// #define tst2_z $VAR_TST2_Z
// #define chk2_z $VAR_CHK2_Z
#define pswd_z $KEY_SIZE

static char msg1 [] = "$VAR_MSG1";
static char date [] = "$VAR_DATE";
static char shll [] = "$VAR_SHLL";
static char inlo [] = "$VAR_INLO";
static char xecc [] = "$VAR_XECC";
static char lsto [] = "$VAR_LSTO";
static char tst1 [] = "$VAR_TST1";
static char chk1 [] = "$VAR_CHK1";
static char msg2 [] = "$VAR_MSG2";
static char rlax [] = "$VAR_RLAX";
static char opts [] = "$VAR_OPTS";
static char text [] = "$VAR_TEXT";
// static char tst2 [] = "$VAR_TST2";
// static char chk2 [] = "$VAR_CHK2";
static char pswd [] = "$VAR_PSWD";

#define      hide_z     4096

/* rtc.c */

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 'Alleged RC4' */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte.
 */
void stte_0(void)
{
        indx = jndx = kndx = 0;
        do {
                stte[indx] = indx;
        } while (++indx);
}

/*
 * Set key. Can be used more than once.
 */
void key(void * str, int len)
{
        unsigned char tmp, * ptr = (unsigned char *)str;
        while (len > 0) {
                do {
                        tmp = stte[indx];
                        kndx += tmp;
                        kndx += ptr[(int)indx % len];
                        stte[indx] = stte[kndx];
                        stte[kndx] = tmp;
                } while (++indx);
                ptr += 256;
                len -= 256;
        }
}

/*
 * Crypt data.
 */
void arc4(void * str, int len)
{
        unsigned char tmp, * ptr = (unsigned char *)str;
        while (len > 0) {
                indx++;
                tmp = stte[indx];
                jndx += tmp;
                stte[indx] = stte[jndx];
                stte[jndx] = tmp;
                tmp += stte[indx];
                *ptr ^= stte[tmp];
                ptr++;
                len--;
        }
}

/* End of ARC4 */

/*
 * Key with file invariants.
 */
int key_with_file(char * file)
{
        struct stat statf[1];
        struct stat control[1];

        if (stat(file, statf) < 0)
                return -1;

        /* Turn on stable fields */
        memset(control, 0, sizeof(control));
        control->st_ino = statf->st_ino;
        control->st_dev = statf->st_dev;
        control->st_rdev = statf->st_rdev;
        control->st_uid = statf->st_uid;
        control->st_gid = statf->st_gid;
        control->st_size = statf->st_size;
        control->st_mtime = statf->st_mtime;
        control->st_ctime = statf->st_ctime;
        key(control, sizeof(control));
        return 0;
}

char * xsh(int argc, char ** argv)
{
        char * scrpt;
        int ret, i, j;
        char ** varg;

        stte_0();
        key(pswd, pswd_z);
        arc4(msg1, msg1_z);
        arc4(date, date_z);
        //if (date[0] && date[0]<time(NULL))
        //        return msg1;
        arc4(shll, shll_z);
        arc4(inlo, inlo_z);
        arc4(xecc, xecc_z);
        arc4(lsto, lsto_z);
        arc4(tst1, tst1_z);
        key(tst1, tst1_z);
        arc4(chk1, chk1_z);
        if ((chk1_z != tst1_z) || memcmp(tst1, chk1, tst1_z))
                return tst1;
        ret = 1;
        arc4(msg2, msg2_z);
        if (ret < 0)
                return msg2;
        varg = (char **)calloc(argc + 10, sizeof(char *));
        if (!varg)
                return 0;
        if (ret) {
                arc4(rlax, rlax_z);
                if (!rlax[0] && key_with_file(shll))
                        return shll;
                arc4(opts, opts_z);
                arc4(text, text_z);
                printf("%s",text);
                return 0;
                /*arc4(tst2, tst2_z);
                key(tst2, tst2_z);
                arc4(chk2, chk2_z);
                if ((chk2_z != tst2_z) || memcmp(tst2, chk2, tst2_z))
                        return tst2;
                if (text_z < hide_z) {
                        scrpt = malloc(hide_z);
                        if (!scrpt)
                                return 0;
                        memset(scrpt, (int) ' ', hide_z);
                        memcpy(&scrpt[hide_z - text_z], text, text_z);
                } else {
                        scrpt = text;
                }*/
        } else {
                if (*xecc) {
                        scrpt = malloc(512);
                        if (!scrpt)
                                return 0;
                        sprintf(scrpt, xecc, argv[0]);
                } else {
                        scrpt = argv[0];
                }
        }
        j = 0;
        varg[j++] = argv[0];            /* My own name at execution */
        if (ret && *opts)
                varg[j++] = opts;       /* Options on 1st line of code */
        if (*inlo)
                varg[j++] = inlo;       /* Option introducing inline code */
        varg[j++] = scrpt;              /* The script itself */
        if (*lsto)
                varg[j++] = lsto;       /* Option meaning last option */
        i = (ret > 1) ? ret : 0;        /* Args numbering correction */
        while (i < argc)
                varg[j++] = argv[i++];  /* Main run-time arguments */
        varg[j] = 0;                    /* NULL terminated array */
        // execvp(shll, varg);
        return shll;
}

int main(int argc, char ** argv)
{
        argv[1] = xsh(argc, argv);
        return 1;
}
EOF
}


if [ $# -lt 1 ]; then
        echo "[?] Type -h or --help for how to use it"
        clean
        exit 0
fi

# Check the availability of each command needed in this script.
check_binaries

OPTS=$( getopt -o h,,d:,s:,o: -l help,dumpfile:,stringfile:,outputfile: -- "$@" )
if [ $? != 0 ]; then
        exit_error;
fi

while [ "$#" -gt 0 ] ; do
        case "$1" in
                -h|--help)
                        usage;
                        clean;
                        exit 0;;
                -d|--dumpfile)
                        echo "[+] Object dump file specified [$2]";
                        DUMPFILE=$2;
                        shift 2;;
                -s|--stringfile)
                        echo "[+] String dump file specified [$2]";
                        STRINGFILE=$2;
                        shift 2;;
                -o|--outputfile)
                        echo "[+] Output file name specified [$2]";
                        OUTPUTFILE=$2;
                        shift 2;;
                -*)
                        echo "[-] Unknown option: [$1]" >&2;
                        exit_error;;
                --)
                        shift;
                        break;;
                *)
                        echo "[*] Input file name to decrypt [$1]";
                        BINARY=$1
                        shift 1;;
        esac
done

if [ ! -e $BINARY ]; then
        echo "[-] Error, File [$BINARY] not found."
        exit_error
fi
if [ -z "$DUMPFILE" ]; then
         DUMPFILE=$(mktemp /tmp/XXXXXX)
else
        if [ ! -e $DUMPFILE ]; then
                echo "[-] Object dump file [$DUMPFILE] not found."
                exit_error;
        fi
fi
if [ -z "$STRINGFILE" ]; then
         STRINGFILE=$(mktemp /tmp/XXXXXX)
else
        if [ ! -e $STRINGFILE ]; then
                echo "[-] String dump file [$STRINGFILE] not found."
                exit_error;
        fi
fi

# Fill DUMPFILE and STRINGFILE from objdump of the *.sh.x encrypted script
generate_dump
# RESULT=0
extract_decrypt_func
RESULT=$?
if [ $RESULT -eq 0 ]; then
    extract_variables_from_dumpfunc
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
        extract_password_from_binary
        generic_file

        # Compile C source code to decrypt *.sh.x file
        $GCC -o $TMPBINARY ${TMPBINARY}.c

        echo "[*] Executing [$TMPBINARY] to decrypt [${BINARY}]"

        chmod +x $TMPBINARY
        if [ -z "$OUTPUTFILE" ]; then
                echo "[*] Retrieving initial source code in [${BINARY%.sh.x}.sh]"
                $TMPBINARY > ${BINARY%.sh.x}.sh
        else
                echo "[*] Retrieving initial source code in [$OUTPUTFILE]"
                $TMPBINARY > $OUTPUTFILE
        fi

        echo "[*] All done!"
        clean
        exit 0
    fi
fi

clean
exit 1