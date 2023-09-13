import sys
import multiprocessing
from importlib import import_module
from datetime import datetime

from python.inequalities import (
    extract_inequality_coefficients,
    get_ineqsign,
    Inequality,
)
import python.version as version
from python.propagation_data import (
    LWEInstance,
    PropagationData,
    PropagationDataStep,
)
from python.solve import solve
from python.helpers import (
    flatten_key,
    check_inequalities,
    bino,
    IneqType,
    print_v,
)

check_bp = import_module(f"check_bp{version.KYBER_VERSION}")
python_kyber = import_module(f"python_kyber{version.KYBER_VERSION}")

verbose = True


def propagate(
    key,
    graph,
    count_steps=1,
    step_size=1,
    thread_count=None,
    propagation_data=None,
):
    if thread_count is None:
        thread_count = multiprocessing.cpu_count()
    success = False
    results_list = graph.get_results(thread_count)
    if propagation_data:
        step_data = PropagationDataStep.new(results_list, key, 0)
        propagation_data.add_step(0, step_data)
    print_v(f"Using {thread_count} threads.\n")
    propagation_data.set_start(datetime.now())
    for step in range(0, count_steps, step_size):
        print_v(f"----Propagation step {step}----")
        graph.propagate(step_size, thread_count)
        print_v("Fetching results..")
        results_list = graph.get_results(thread_count)
        #        results = {i: results_list[i] for i in range(len(key))}
        step_data = PropagationDataStep.new(results_list, key, step + step_size)
        if propagation_data:
            propagation_data.add_step(step + step_size, step_data)
        print_v(f"Average entropy is {step_data.avg_entropy}.")
        print_v(f"Maximal entropy is {step_data.max_entropy}.")
        print_v("")
        print_v(f"{step_data.recovered_coefficients} coefficients recovered")
        if step_data.guessed_key == key:
            print_v("Found correct key.")
            success = True
            break
        if step_data.recovered_coefficients >= len(key) // 2:
            print_v("Found enough correct coefficients")
            success = True
            break
    propagation_data.set_end(datetime.now())
    if success:
        print_v("BP alone: Success!")
    else:
        print_v("BP alone: Failure!")
    return success


def create_graph_inequalities(ineqs, dist):
    print_v("Building check graph..")
    g = check_bp.CheckGraph()
    g.add_var_nodes(dist)
    lineno = 0
    total = len(ineqs)
    corrects = 0
    for ineq in ineqs:
        if ineq.p_correct < 1.0:
            g.add_inequality_prob(
                f"Line {lineno}",
                ineq.coefficients,
                ineq.b,
                ineq.sign == IneqType.LE,
                ineq.p_correct,
            )
        else:
            g.add_inequality(
                f"Line {lineno}",
                ineq.coefficients,
                ineq.b,
                ineq.sign == IneqType.LE,
            )
            corrects += 1
        lineno += 1
        print_v(f"{lineno}/{total}\t\t", end="\r")
    print_v("                                          ")
    print_v(f"Created {total} inequalities, {corrects} are certainly correct, {total-corrects} might be incorrect.")
    print_v("Initializing graph..")
    g.ini()
    return g

#This is the function which produces the inequalities
def sample_inequalities(
    number_faults,
    p_correct,
    max_delta_v=None,
    num_certain_correct=None,
    default_sign = None,
    ineq_always_correct = None,
    offset = 0,
):
    if num_certain_correct is None:
        if p_correct < 1.0:
            num_certain_correct = 0
        else:
            num_certain_correct = number_faults 
    sample = python_kyber.KyberSample.generate(True)
    print_v("Sampling inequalities..")
    # sample = sample_from_key_bytes(sk_bytes, pk_bytes, e_lists)
    if not ineq_always_correct:
        print_v(
            f"kyber_version={version.KYBER_VERSION}, number_faults={number_faults}, p={p_correct}, certainly_correct={num_certain_correct}, max_delta_v={max_delta_v}, inequality preference = {default_sign}, offset = {offset}"
        )
    else:
        print_v(
            f"kyber_version={version.KYBER_VERSION}, number_faults={number_faults}, p={p_correct}, certainly_correct={ineq_always_correct}, max_delta_v={max_delta_v}, inequality preference = {default_sign}, offset = {offset}"
        )
    if default_sign:
        if default_sign == "ge":
            default_sign = IneqType.GE
        elif default_sign == "le":
            default_sign = IneqType.LE
    if ineq_always_correct:
        if ineq_always_correct == "ge":
            ineq_always_correct = IneqType.GE
        elif ineq_always_correct == "le":
            ineq_always_correct = IneqType.LE
    key = flatten_key(sample)
    lwe_instance = LWEInstance.from_mlwe(sample)
    inequalities = []
    no_ineqs = 0
    errors = 0
    filtered_cts = 0
    ge_ineq = 0
    le_ineq = 0
    for i in range(number_faults):
        is_correct = True
        coeffs = None
        b = None
        first = True
        while not coeffs:
            sample = python_kyber.KyberSample.generate_with_key(
                False, sample.pk, sample.sk, sample.e
            )
            coeffs, b = extract_inequality_coefficients(sample, max_delta_v=max_delta_v)
            if not first:
                filtered_cts += 1
            first = False
        sign = get_ineqsign(sample)
        if get_ineqsign == IneqType.GE:
            ge_ineq+=1
        elif get_ineqsign == IneqType.LE:
            le_ineq+=1
        if ineq_always_correct:
            if sign == ineq_always_correct:
                p_correct_ineq = 1
            else:
                p_correct_ineq = p_correct
            if sign == IneqType.GE:
                b-=offset
            else:
                b+=offset
            inequalities.append(Inequality(coeffs, sign, b, is_correct, p_correct_ineq))
            no_ineqs += 1
            print_v(f"{i}/{number_faults}\t\t", end="\r")
        elif ineq_always_correct==None:
            if i >= ((number_faults - num_certain_correct) * p_correct) + num_certain_correct:
                is_correct = False
                p_correct_ineq = p_correct
                errors += 1
                if sign == IneqType.LE:
                    sign = IneqType.GE
                else:
                    sign = IneqType.LE
            else:
                p_correct_ineq = 1 if i < num_certain_correct else p_correct
            #The new code for the option of choosing only one type of inequality is given below
            if default_sign:
                if sign == default_sign:
                    if sign == IneqType.GE:
                        b-=offset
                    else:
                        b+=offset   
                    inequalities.append(Inequality(coeffs, sign, b, is_correct, p_correct_ineq))
                    no_ineqs += 1
                    print_v(f"{i}/{number_faults}\t\t", end="\r")
            else:
                if sign == IneqType.GE:
                    b-=offset
                else:
                    b+=offset
                inequalities.append(Inequality(coeffs, sign, b, is_correct, p_correct_ineq))
                no_ineqs += 1
                print_v(f"{i}/{number_faults}\t\t", end="\r") 
    if offset==0:  
        assert check_inequalities(key, inequalities)
    print_v("                                          ")
    print_v("Number of inequalities: ", no_ineqs)
    print_v(f"Wrong inequalities: {errors}")
    print_v(f"Filtered cts: {filtered_cts}")
    print_v("Finished sampling inequalities.")
    propagation_data = PropagationData.new(
        key, inequalities, filtered_cts, max_delta_v, lwe_instance
    )
    sys.stdout.flush()
    return propagation_data


def run_with_inequalities(
    propagation_data,
    steps,
    step_size,
    block_size,
    run_reduction,
    max_beta,
    add_fplll,
    use_best_step,
    max_enum,
):
    if len(propagation_data.steps) == 0:
        g = create_graph_inequalities(
            propagation_data.inequalities,
            bino(python_kyber.KyberConstants.ETA()),
        )
        success_bp = propagate(
            propagation_data.key,
            g,
            steps,
            step_size,
            propagation_data=propagation_data,
        )
    elif propagation_data.steps:
        steps = sorted(propagation_data.steps.items(), key=lambda x: x[0])
        success_bp = steps[-1][1].recovered_coefficients
    else:
        success_bp = None
    print("BP alone " + "succeeded" if success_bp else "did not succeed" + ".")
    step_idx = (
        max(
            propagation_data.steps,
            key=lambda x: propagation_data.steps[x].correct_coefficients,
        )
        if use_best_step
        else -1
    )
    step_list = sorted(propagation_data.steps.items(), key=lambda x: x[0])
    pos = 0
    for idx, _ in reversed(step_list):
        if idx == step_idx:
            break
        pos += 1
    print_v(
        f"Using step {step_idx} which is on position {pos}, has {propagation_data.steps[step_idx].correct_coefficients} correct coefficients and {propagation_data.steps[step_idx].recovered_coefficients} recovered coefficients."
    )
    propagation_data.recovered_coefficients = propagation_data.steps[
        step_idx
    ].recovered_coefficients
    success = solve(
        propagation_data,
        block_size=block_size,
        run_reduction=run_reduction,
        max_beta=max_beta,
        perform=run_reduction,
        add_fplll=add_fplll,
        step=step_idx,
        max_enum=max_enum,
        step_rank=pos,
    )
    return success, propagation_data
