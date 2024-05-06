rm -r batch_query_test_log
mkdir batch_query_test_log
cd batch_query_test_log

for ((i = 8 ; i <= 12; i++)) 
do
    for j in 1 
    do
        l=$((2**i))
	    echo "../../bin/pirexamples -b 1 -l $l -n 16384 -x 20480 -c 1 >> batch_query.txt"
	    ../../bin/pirexamples -b 1 -l $l -n 16384 -x 20480 -c 1 >> batch_query.txt
    done
done

# for ((i = 8 ; i <= 12; i++)) 
# do
#     for j in 1 
#     do
#         l=$((2**i))
# 	    echo "../../bin/pirexamples -b 1 -l $l -n 1048576 -x 256 -c 0 >> batch_query.txt"
# 	    ../../bin/pirexamples -b 1 -l $l -n 1048576 -x 256 -c 0 >> batch_query.txt
#     done
# done
