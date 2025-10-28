start=$(date +%s.%N)
# Your command here
./build/vm --run examples/ftest.s
dur=$(echo "$(date +%s.%N) - $start" | bc)
printf "Execution time: %.6f seconds\n" $dur

