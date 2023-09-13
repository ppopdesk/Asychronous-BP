# Instructions for running

1) To install ensure that recent rust and python3 versions are installed.
2) Then use "source setup.sh" to create the virtual environment (virtualenv needs to be installed), source it, compile the modified PQClean and the rust packages, and install python packages.
3) To start a recovery then use "python3 recover.py new 10000" (with no ciphertext filtering and 10000 newly sampled inequalities).
4) There is also option available to recover in a filtered scenario as in the paper you may use "python3 recover.py new --max-delta-v 10 6000"
5) We can sample inequalities (lets say 10000) and give options such that some of the inequalities are correct with p=1 (lets say 6000) and the rest are correct with lets say some p=0.8 . This can be executed using the command : 'python3 recover.py new --p-correct 0.8 --certain-correct 6000 10000'

The new features added are:

1) There has been added a feature in which we can enable an option such that only inequalities of a particular type (lets say 'ge') are sample. In this case if we want to work on some n number of inequalities of a particular type we must run for 2n faults. command for this option is : 'python3 recover.py new --ineq-always-correct ge 12000'.
2) There is a feature for sampling inequalities such that an inequality of one type (lets say ge) is always correct with p=1 and the other type of inequality is correct with some probability p. This ofcourse makes sense only if this p is also given and is less than 1. command for executing this : 'python3 recover.py new --ineq-always-correct le --p-correct 0.8 15000'.
3) There is a feature for offseting the value of b in the inequality using the command : 'python3 recover.py new --offset 10 15000'. In this case using the value k=10.