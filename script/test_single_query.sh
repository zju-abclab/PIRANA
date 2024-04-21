rm -r single_query_test_log
mkdir single_query_test_log
cd single_query_test_log
for ((i = 13 ; i <= 16; i++)) 
do
    for j in 1 
    do
        n=$((2**i))
        echo "../../bin/pirexamples -b 0 -l 1 -n $n -x 20480 >> single_query.txt"
	    ../../bin/pirexamples -b 0 -l 1 -n $n -x 20480 >> single_query.txt
    done
done