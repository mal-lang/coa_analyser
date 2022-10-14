from securicad import enterprise
from securicad.model import Model
from attack_graph import AttackGraph, merge_attack_graphs
from json_helpers import read_json_file, write_json_file
import configparser
import argparse
import logging
import json
import zipfile
import base64
import os
import xml.etree.ElementTree as ET
import numpy as np
import sys
import warnings

TEMP_INF = 1.7976931348623157e+308

SUCCESS = 0
ERROR_INCORRECT_CONFIG = 1
ERROR_FAILED_SIM = 2
ERROR_NO_DEFENCE = 3
ERROR_UNKNOWN_METRIC = 4

MAX_SIMULATION_CREATION_RETRIES = 5

# suppressing HTTPS insecure connection warnings
suppress = True
if suppress and not sys.warnoptions:
    warnings.simplefilter("ignore")

def calculate_efficiency(previous_ttcs, current_ttcs):
    '''
    previous_ttcs and current_ttcs are dictionaries with the same keys, with
    values being lists of length at least two.

    previous_ttcs[x][0] = previous_ttcs ttc5 for the attack step x
    previous_ttcs[x][1] = previous_ttcs ttc50 for the attack step x

    current_ttcs[x][0] = current_ttcs ttc5 for the attack step x
    current_ttcs[x][1] = current_ttcs ttc50 for the attack step x

    NOTE: securiCAD migth return previous ttc5 equal to zero. this is not good
    for this efficiency metric. Also, it doesn't make sense for the attack
    steps that are not initially compromised. So, previous_ttcs 0 values will
    be changed to 0.001
    '''
    result = 0
    c = 150
    for x in previous_ttcs:
        previous_ttcs5 = max(previous_ttcs[x][0], 0.001)
        previous_ttcs50 = max(previous_ttcs[x][1], 0.001)
        current_ttcs5 = max(current_ttcs[x][0], 0.001)
        current_ttcs50 = max(current_ttcs[x][1], 0.001)
        logging.debug(f"within Efficiency ttc5: {previous_ttcs[x][0]} " +
            f"ttc50: {previous_ttcs[x][1]}")
        if previous_ttcs[x][0] != TEMP_INF:
            if previous_ttcs[x][1] == TEMP_INF:
                # ttc5_i is finite, ttc50_i is not
                result += np.power(1.05, -previous_ttcs5) * min(current_ttcs5 - previous_ttcs5, c)
            else:
                # ttc5_i is finite, ttc50_i is also finite
                result += np.power(1.05, -previous_ttcs5) * \
                    min(current_ttcs5 - previous_ttcs5, c) + np.power(1.05, -previous_ttcs50) * \
                    min(current_ttcs50 - previous_ttcs50, c)
    return round(result, 3)

def create_simulation(client, scenario, name, iteration, model, tunings = []):

        # create new simulation
        retries = 0
        samples = 100
        simulation = None

        while retries < MAX_SIMULATION_CREATION_RETRIES:
            try:
                model.model["samples"] = samples
                logging.info(f'For iteration {iteration} create new ' +
                    'simulation with the following tunings:\n' +
                    json.dumps(tunings, indent = 2))
                simulation = client.simulations.create_simulation(scenario,
                    name = name + " s=" + str(samples), model = model, raw_tunings = tunings)
                simres = simulation.get_results()

                if simres:
                    logging.info(f'Simulation {name} ran successfully')
                    logging.debug(f'Simulation results for {name}:\n' +
                        json.dumps(simres, indent = 2))
                    return simulation, simres

            except Exception as e:
                retries += 1
                if retries < MAX_SIMULATION_CREATION_RETRIES:
                    samples = samples + 100 * retries
                    logging.warning(f"Simulation failed with:\n{e}\n" +
                        "Retrying failed simulation with more samples.\n" +
                        f"Retries:{retries}. Retrying with {samples} " +
                        "samples.")

        logging.error("Simulation failed")
        print("Simulation failed")
        return None, None

def update_costs_from_file(costsfile, lang_meta):
    survey_costs = None
    with open(costsfile, 'r') as f:
        survey_costs = json.load(f)

    logging.debug(f"Costs updates found in {costsfile}:\n" +
        json.dumps(survey_costs, indent = 2))

    for asset in lang_meta["assets"]:
        for defense in lang_meta["assets"][asset]["defenses"]:
            if asset in survey_costs and \
                defense["name"] in survey_costs[asset]:
                defense["metaInfo"]["cost"] = survey_costs[asset][defense["name"]]

def run_coa():

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--logfile', default='log.txt',
        help='filename to use for the log (default: %(default)s)')
    parser.add_argument('-c', '--configfile', default='coa.ini',
        help='filename to use for the configuration (default: %(default)s)')
    parser.add_argument('-o', '--costsfile',
        help='filename to use for the costs')
    parser.add_argument('-r', '--resultsfile', default='results.json',
        help='filename to use for the results (default: %(default)s)')
    parser.add_argument('-m', '--metric', default='frequency',
        help='metric used to find the most critical attack step (default: %(default)s)')
    parser.add_argument('-i', '--max_iterations', type=int, default=100,
        help='number of maximum simulation iterations the analyser will ' +
            'run (default: %(default)s)')
    parser.add_argument('-b', '--initial_budget', type=int, default=1000,
        help='initial budget (default: %(default)s)')
    parser.add_argument('-n', '--simulation_name_prefix', default="",
        help='simulation name prefix (default: %(default)s)')

    args = vars(parser.parse_args())
    logfile = args['logfile']
    configfile = args['configfile']
    costsfile = args['costsfile']
    resultsfile = args['resultsfile']
    metric = args['metric']
    max_iterations = args['max_iterations']
    initial_budget = args['initial_budget']
    simulation_name_prefix = args['simulation_name_prefix']

    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename=logfile,
                    filemode='w')

    if os.path.isfile(resultsfile):
        os.remove(resultsfile)
    config = configparser.ConfigParser()
    config.read(configfile)

    budget_remaining = initial_budget
    logging.info(f"Starting budget: {budget_remaining}")

    # Create an authenticated enterprise client

    logging.info("Log in to Enterprise.")
    client = enterprise.client(
        base_url=config["enterprise-client"]["url"],
        username=config["enterprise-client"]["username"],
        password=config["enterprise-client"]["password"],
        organization=config["enterprise-client"]["org"] if config["enterprise-client"]["org"] else None,
        cacert=config["enterprise-client"]["cacert"] if config["enterprise-client"]["cacert"] else False
    )
    logging.info("Successfully logged on to Enterprise.")

    # Must "cheat" here and call a raw API to obtain full language meta.
    # The SDK method client.metadata.get_metadata() will not provide everything needed.
    lang_meta = client._get("metadata")

    if (costsfile):
        update_costs_from_file(costsfile, lang_meta)
        logging.debug("Client's language metadata after costs update:\n" +
            json.dumps(lang_meta, indent = 2))

    if "project" in config and "name" in config["project"] and \
        config["project"]["name"]:
        # Get the project where the model will be added
        project_name = config["project"]["name"]
        project = client.projects.get_project_by_name(name = project_name)

    else:
        logging.critical('Could not find project or project name in ' +
            f'{configfile} config file.')
        print('Could not find project or project name in',
            f'{configfile} config file.')
        return ERROR_INCORRECT_CONFIG

    if  "scenario" in config["project"] and config["project"]["scenario"]:
        scenario = client.scenarios.get_scenario_by_name(project = project,
            name = config["project"]["scenario"])
    else:
        logging.critical(f'Could not find scenario in {configfile} '
            + 'config file.')
        print(f'Could not find scenario in {configfile} config file.')
        return ERROR_INCORRECT_CONFIG

    if "simID" in config["project"] and config["project"]["simID"]:
        simID = config["project"]["simID"]
        res = client._post("model/file", data={"pid": project.pid, "mids": [simID]})
        base_model_dict = client._post("model/json", data={"pid": project.pid, "mids": [simID]})
        model = Model(base_model_dict)
        resp = client._post("scenarios", data={"pid": project.pid})
        logging.info(f"Loaded initial simulation with project name: " +
            f"{project_name} and simulation id: {simID}")

        simulations = enterprise.simulations.Simulations(client)
        simulation = client.simulations.get_simulation_by_simid(scenario, simID)
        model_name = simulation.name
        scad_dump = base64.b64decode(res["data"].encode("utf-8"), validate=True)

    elif "model" in config["project"] and config["project"]["model"]:
        model_name = config["project"]["model"]
        models = enterprise.models.Models(client)
        modelinfo = models.get_model_by_name(project, model_name)
        model = modelinfo.get_model()
        scad_dump = modelinfo.get_scad()
    else:
        logging.critical('Could not find simulation id or model name in ' +
            f'{configfile} config file.')
        print('Could not find simulation id or model name in',
            f'{configfile} config file.')
        return ERROR_INCORRECT_CONFIG

    if simulation_name_prefix:
        simulation_name = simulation_name_prefix + " " + model_name + " "
    else:
        simulation_name = model_name + " "
    simulation, simres = create_simulation(client = client,
        scenario = scenario, name = simulation_name + "Initial Simulation",
        model = model, iteration = -1)

    if not simres:
        return ERROR_FAILED_SIM

    # download the model
    datapath = 'data-models'
    if not os.path.exists(datapath):
        os.makedirs(datapath)
    model_path = "data-models/temp.sCAD"
    f1 = open(model_path, "wb")
    f1.write(scad_dump)
    f1.close()

    # unzip the model
    model_dir_path = model_path[:model_path.rindex('/')]
    model_file_name = model_path[model_path.rindex('/') + 1:model_path.rindex('.')]
    unzip_dir = "scad_dir"
    unzip_dir_path = "{}/{}".format(model_dir_path, unzip_dir)
    with zipfile.ZipFile(model_path, 'r') as zip_ref:
        zip_ref.extractall(unzip_dir_path)
    eom_path = "{}/{}.eom".format(unzip_dir_path, model_name)

    # delete the downloaded model file
    os.remove(model_path)

    # xml parsing
    with open(eom_path, 'rt') as f:
        tree = ET.parse(f)
        root = tree.getroot()

    model_dict_list = []

    for object in root.iter("objects"):
        model_dict = {}
        model_dict["name"] = object.attrib['name']
        model_dict["metaConcept"] = object.attrib['metaConcept']
        model_dict["exportedId"] = object.attrib['exportedId']
        model_dict["attributesJsonString"] = json.loads(object.attrib['attributesJsonString'])
        model_dict_list.append(model_dict)

    raw_tunings = []

    previous = {}
    data = read_json_file(resultsfile)
    if "CoAs" not in data.keys():
        data["CoAs"] = []

    for main_i in range(max_iterations):
        logging.debug(f'Current results at iteration {main_i}:\n' +
            json.dumps(data, indent = 2))
        if "previous_TTC" not in data.keys():
            data["previous_TTC"] = {}

        ttcs = {}
        saved_simid = simres["simid"]
        if "simID" in config["project"] and config["project"]["simID"]:
            data["final_simid"] = saved_simid
            data["initial_simid"] = simID
        if "model" in config["project"] and config["project"]["model"]:
            data["initial_ids"] = {"pid": project.pid, "tid": scenario.tid, "simid": "1"}

        for risks_i in simres["results"]["risks"]:
            ttcs[risks_i["attackstep_id"]] = [round(float(risks_i["ttc5"]), 3), round(float(risks_i["ttc50"]), 3), round(float(risks_i["ttc95"]), 3)]

            previous_ttcs_json = ttcs[risks_i["attackstep_id"]]
            for i in model_dict_list:
                if i['exportedId'] == risks_i['object_id']:
                    refnumber = risks_i['object_id']
                    try:
                        refnumber = i['attributesJsonString']['ref']
                    except:
                        pass
            risk_index = refnumber + "." + risks_i['attackstep']
            if main_i == 0:
                data["previous_TTC"][risk_index] = previous_ttcs_json
            else:
                coa_index = len(data["CoAs"]) - 1
                if "coaTTC" not in data["CoAs"][coa_index].keys():
                    data["CoAs"][coa_index]["coaTTC"] = {}
                data["CoAs"][coa_index]["coaTTC"][risk_index] = previous_ttcs_json
                data["CoAs"][coa_index]["report_url"] = simres["report_url"]

        write_json_file(resultsfile, data)
        steps_of_interest = ["{}".format(risks_i["attackstep_id"]) for risks_i in simres["results"]["risks"]]
        logging.debug("Steps of interest are:\n" +
            json.dumps(steps_of_interest, indent = 2))

        if main_i != 0:
            eff = calculate_efficiency(previous_ttcs, ttcs)
            logging.debug(f"Efficiency for step {main_i} is {eff}")
            data["CoAs"][coa_index]["efficiency"] = str(eff)
            write_json_file(resultsfile, data)

        previous_ttcs = ttcs

        attack_paths = []

        # get selected critical paths - where ttc5 is less than infinity
        for risks_i in simres["results"]["risks"]:
            if round(float(risks_i["ttc5"]), 3) == TEMP_INF:
                continue
            cri_path = simulation.get_critical_paths([risks_i["attackstep_id"]])
            logging.debug("Critical path fetched:\n" +
                json.dumps(cri_path, indent = 2))
            ag = AttackGraph(cri_path, risks_i["attackstep_id"], lang_meta)
            logging.debug("Critical path converted to an attack graph.")
            attack_paths.append(ag)

        if len(attack_paths) == 0:
            logging.info("Simulation terminating successfully after " +
                "protecting all of the high value assets.")
            return SUCCESS

        graph = merge_attack_graphs(attack_paths)

        if (graph.find_critical_attack_step(metric) != 0):
            return ERROR_UNKNOWN_METRIC

        write_json_file(resultsfile, data)
        best_def_info, budget_remaining = graph.find_best_defense(lang_meta,
            model_dict_list, budget_remaining, resultsfile)
        data = read_json_file(resultsfile)
        if (best_def_info):
            logging.info(f"Best defense for iteration {main_i} is:\n" +
                json.dumps(best_def_info, indent = 2))
            logging.info(f"Remaining budget after iteration {main_i} is " +
                f"{budget_remaining}")
            raw_tunings.append(
                {
                    "type": "probability",
                    "op": "apply",
                    "filter": {"object_name": best_def_info["name"], "defense": best_def_info["attackstep"],
                               "tags": {"ref": best_def_info["ref"]}},
                    "probability": 1.0
                }
            )
        else:
            logging.error("Failed to find an applicable defense for " +
                f"iteration {main_i}.")
            return ERROR_NO_DEFENCE
        data = read_json_file(resultsfile)

        simulation, simres = create_simulation(client = client,
            scenario = scenario,
            name = simulation_name + " i=" + str(main_i),
            iteration = main_i, model = model, tunings = raw_tunings)

        if not simres:
            return ERROR_FAILED_SIM

    logging.error("Ran the maximum number of " +
    f"simulations allowed({max_iterations}) without finding all the " +
    "defenses required to stop all of the attacks on high value assets.")
    print("Ran the maximum number of " +
    f"simulations allowed({max_iterations}) without finding all the " +
    "defenses required to stop all of the attacks on high value assets.")

if __name__ == "__main__":
    exit(run_coa())
