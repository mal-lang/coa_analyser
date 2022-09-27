import base64

from securicad import enterprise
import configparser
import re
import json
import zipfile
import shutil
import os
from securicad.model import Model
import xml.etree.ElementTree as ET
import json
import numpy as np
from attackg import AttackGraph, merge_attack_graphs
import sys
import warnings
import time
import logging

def read_json_file(filename):
    if os.path.isfile(filename):
        with open(filename, 'r') as json_file:
            return json.load(json_file)
    else:
        return {}


def write_json_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent = 4)

JSON_FILENAME = "results.json"
final_result = {}

LOG_FILENAME = "log.txt"

temp_inf = 1.7976931348623157e+308

from flask import Flask, request

app = Flask(__name__)

# suppressing HTTPS insecure connection warnings
suppress = True
if suppress and not sys.warnoptions:
    warnings.simplefilter("ignore")

################# your input required

def efficiency(initial, final):
    '''
    initial and final are dictionaries with the same keys, with values being lists of length at least two.

    initial[x][0] = initial ttc5 for the attack step x
    initial[x][1] = initial ttc50 for the attack step x

    final[x][0] = final ttc5 for the attack step x
    final[x][1] = final ttc50 for the attack step x

    NOTE: securiCAD migth return initial ttc5 equal to zero. this is not good for this efficiency metric.
    also, it doesn't make sense for the attack steps that are not initially compromised.
    so, initial 0 values will be changed to 0.001
    '''
    result = 0
    c = 150
    for x in initial:
        initial5 = max(initial[x][0], 0.001)
        initial50 = max(initial[x][1], 0.001)
        final5 = max(final[x][0], 0.001)
        final50 = max(final[x][1], 0.001)
        logging.debug("within Efficiency ttc5 {} - ttc50 {} - ".format(initial[x][0], initial[x][1]))
        if initial[x][0] != temp_inf:
            if initial[x][1] == temp_inf:
                # ttc5_i is finite, ttc50_i is not
                result += np.power(1.05, -initial5) * min(final5 - initial5, c)
            else:
                # ttc5_i is finite, ttc50_i is also finite
                result += np.power(1.05, -initial5) * min(final5 - initial5, c) + np.power(1.05, -initial50) * min(
                    final50 - initial50, c)
    return round(result, 3)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename=LOG_FILENAME,
                    filemode='w')

    if os.path.isfile(JSON_FILENAME):
        os.remove(JSON_FILENAME)
    config = configparser.ConfigParser()
    config.read('coa.ini')

    budget_remaining = 20000
    logging.info(f"Starting budget: {budget_remaining}")

    # Create an authenticated enterprise client
    #to get the results with the simid and get the model_id by taking results["model_data"]["mid"] and then model = get_model_by_mid(model_id)

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
    logging.debug("Client's language metadata:\n" +
        json.dumps(lang_meta, indent = 2))

    survey_costs = None
    with open('./costs_survey.json', 'r') as f:
        survey_costs = json.load(f)

    def_cat = "User"
    def_name = "SecurityAwareness"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "SoftwareVulnerability"
    def_name = "Remove"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Identity"
    def_name = "Disabled"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Group"
    def_name = "Disabled"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Privileges"
    def_name = "Disabled"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Directory"
    def_name = "Disabled"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Hardware"
    def_name = "HardwareModificationsProtection"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Application"
    def_name = "Disabled"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "ConnectionRule"
    def_name = "Restricted"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Credentials"
    def_name = "NotDisclosed"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Credentials"
    def_name = "NotPhishable"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    def_cat = "Network"
    def_name = "ManInTheMiddleDefense"
    svds = lang_meta["assets"][def_cat]["defenses"]
    svr = next((d for d in svds if d["name"] == def_name), False)
    svr["metaInfo"]["cost"] = survey_costs[def_cat][def_name]
    svr["metaInfo"]["cost_time"] = [30, 10]

    logging.debug("Survey costs found.\n" +
        json.dumps(survey_costs, indent = 2))

    # Get the project where the model will be added
    project = client.projects.get_project_by_name(name=config["project"]["name"])
    simID = "198799675036799"
    res = client._post("model/file", data={"pid": project.pid, "mids": [simID]})
    base_model_dict = client._post("model/json", data={"pid": project.pid, "mids": [simID]})
    base_model = Model(base_model_dict)
    scenario = client.scenarios.get_scenario_by_name(project=project,
        name=config["project"]["scenario"])
    resp = client._post("scenarios", data={"pid": project.pid})
    logging.info(f"Project pid: {project.pid} SimID: {simID}")
    for scenario_id, scenario_data in resp.items():
        if scenario_id == scenario.tid:
            logging.debug(f'Received scenario data: {scenario_data["basemodel"]}')
            break

    simulations = enterprise.simulations.Simulations(client)
    #simulation = simulations.get_simulation_by_simid(project, simID)
    #scenario = client.scenarios.get_scenario_by_name(project, scenario)
    simulation = client.simulations.get_simulation_by_simid(scenario, simID)
    logging.debug(f'Simulation TID: {simulation.tid} Name: {simulation.name}')

    scad_dump = base64.b64decode(res["data"].encode("utf-8"), validate=True)

    # Get the model info for the target model from the project

    #models = enterprise.models.Models(client).list_models(project)

    models = enterprise.models.Models(client)

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
    #eom_path = "{}/{}.eom".format(unzip_dir_path, modelinfo.name)
    eom_path = "{}/{}.eom".format(unzip_dir_path, simulation.name)

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


    # Fetch scenario
    scenarios = enterprise.scenarios.Scenarios(client)
    scenario = client.scenarios.get_scenario_by_name(project, "soccrates")

    logging.info('New scenario created.')

    raw_tunings = []

    previous = {}
    data = read_json_file(JSON_FILENAME)
    if "CoAs" not in data.keys():
        data["CoAs"] = []

    MAX_ITERATIONS = 100
    for main_i in range(MAX_ITERATIONS):
        logging.debug(f'Current results at iteration {main_i}:\n' +
            json.dumps(data, indent = 2))
        if "initialTTC" not in data.keys():
            data["initialTTC"] = {}

        # create simulation
        simres = {}
        simulation = None
        MAX_RETRIES = 5
        retries = 0
        samples = 100

        while retries < MAX_RETRIES:
            try:
                if main_i == 0:
                    simulation = client.simulations.get_simulation_by_simid(scenario, simID)
                    logging.info("Fetched initial simulation.")
                else:
                    base_model.model["samples"] = samples
                    logging.info(f'For iteration {main_i} create new ' +
                        'simulation with the following tunings:\n' +
                        json.dumps(raw_tunings, indent = 2))
                    simulation = client.simulations.create_simulation(scenario,
                        name="AB w/T i=" + str(main_i) + " s=" + str(samples),
                        model=base_model,
                        raw_tunings=raw_tunings)

                # get ttc values
                simres = simulation.get_results()
                break

            except Exception as e:
                retries += 1
                samples = samples + 100 * retries
                logging.warning(f"Simulation failed with:\n{e}" +
                    "Retrying failed simulation with more samples.\n" +
                    f"Retries:{retries}. Retrying with {samples} samples.")

        if simulation is None:
            logging.error("Simulation failed")
            break

        ttcs = {}
        ttcx = {}
        saved_simid = simres["simid"]
        data["final_simid"] = saved_simid
        data["initial_simid"] = simID
        for risks_i in simres["results"]["risks"]:
            ttcs[risks_i["attackstep_id"]] = [round(float(risks_i["ttc5"]), 3), round(float(risks_i["ttc50"]), 3), round(float(risks_i["ttc95"]), 3)]
            ttcx[risks_i["attackstep_id"]] = [round(float(risks_i["ttc5"]), 3), round(float(risks_i["ttc50"]), 3)]

            if main_i == 0:
                initial_ttcs_json = ttcs[risks_i["attackstep_id"]]
                for i in model_dict_list:
                    if i['exportedId'] == risks_i['object_id']:
                        refnumber = risks_i['object_id']
                        try:
                            refnumber = i['attributesJsonString']['ref']
                        except:
                            pass
                risk_index = refnumber + "." + risks_i['attackstep']
                data["initialTTC"][risk_index] = initial_ttcs_json
            else:
                initial_ttcs_json = ttcs[risks_i["attackstep_id"]]
                coa_index = len(data["CoAs"]) - 1
                if "coaTTC" not in data["CoAs"][coa_index].keys():
                    data["CoAs"][coa_index]["coaTTC"] = {}

                for i in model_dict_list:
                    if i['exportedId'] == risks_i['object_id']:
                        refnumber = risks_i['object_id']
                        try:
                            refnumber = i['attributesJsonString']['ref']
                        except:
                            pass
                risk_index = refnumber + "." + risks_i['attackstep']

                data["CoAs"][coa_index]["coaTTC"][risk_index] = initial_ttcs_json
                data["CoAs"][coa_index]["report_url"] = simres["report_url"]

            write_json_file(JSON_FILENAME,data)
        steps_of_interest = ["{}".format(risks_i["attackstep_id"]) for risks_i in simres["results"]["risks"]]
        logging.debug("Steps of interest are:\n" +
            json.dumps(steps_of_interest, indent = 2))

        if main_i == 0:
            previous = ttcx
        else:
            eff = efficiency(previous, ttcx)
            previous = ttcx
            logging.debug(f"Efficiency for step {main_i} is {eff}")
            data["CoAs"][coa_index]["efficiency"] = str(eff)
            write_json_file(JSON_FILENAME, data)

        attack_paths = []

        # get selected critical paths - where ttc5 is less than infinity
        for risks_i in simres["results"]["risks"]:
            if round(float(risks_i["ttc5"]), 3) == temp_inf:
                continue
            cri_path = simulation.get_critical_paths([risks_i["attackstep_id"]])
            logging.debug("Critical path fetched:\n" +
                json.dumps(cri_path, indent = 2))
            ag = AttackGraph(cri_path, risks_i["attackstep_id"], lang_meta)
            logging.debug("Critical path converted to an attack graph.")
            attack_paths.append(ag)

        if len(attack_paths) == 0:
            exit()

        # code for debugging

        graph = merge_attack_graphs(attack_paths)

        crit_metric = ['o', 'f']
        for i in range(len(crit_metric)):
            graph.find_critical_attack_step(crit_metric[i])

        write_json_file(JSON_FILENAME,data)
        try:
            best_def_info, budget_remaining = graph.find_best_defense(lang_meta, model_dict_list, budget_remaining)
            data = read_json_file(JSON_FILENAME)

            logging.info(f"Best defence for iteration {main_i} is:\n" +
                json.dumps(best_def_info, indent = 2))
            logging.info(f"Remaining budget after iteration {main_i} is",
                f"{remaining_budget}")
            raw_tunings.append(
                {
                    "type": "probability",
                    "op": "apply",
                    "filter": {"object_name": best_def_info["name"], "defense": best_def_info["attackstep"],
                               "tags": {"ref": best_def_info["ref"]}},
                    "probability": 1.0
                }
            )
        except:
            logging.error("Error with defense fetching, maybe UUID??")
            data = read_json_file(JSON_FILENAME)


@app.route('/', methods=["POST"])
def hello():
    if request.is_json:
        request_data = request.get_json()
        print("JSON Simulation ID : {}".format(request_data['simulationId']))
    else:
        req = request.data
        print("request.data : {}".format(request.data))
        request_data = json.loads(req.decode('ascii'))
        print("Non JSON Simulation ID : {}".format(request_data['simulationId']))

    results = '{'
    with open('newTestsResults.txt', 'w') as f:
        f.write(results)

    #connect(1)

    results =  ']}'
    with open('newTestsResults.txt', 'a') as f:
        f.write(results)

    with open("newTestsResults.txt", "rb") as fin:
        content = json.load(fin)
    with open("stringJson.txt", "w") as fout:
        json.dump(content, fout, indent = 1)
        R = json.dumps(content)

    return R
