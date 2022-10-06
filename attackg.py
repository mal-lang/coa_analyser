import json
import os
import networkx as nx
import logging

def read_json_file(filename):
    if os.path.isfile(filename):
        with open(filename, 'r') as json_file:
            return json.load(json_file)
    else:
        return {}


def write_json_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

class AttackGraph(nx.DiGraph):

    def __init__(self, path = None, target = None, metadata = None):
        self.nodes_sorted = []
        super().__init__()
        self._get_params_from_json(path, target, metadata)


    def _get_params_from_json(self, path = None, target = None, metadata = None):
        if path is None:
            return
        # finding out the edges by index values
        edges_by_indices = []
        for link in path[target]["links"]:
            edges_by_indices.append((link["source"], link["target"]))
        # map index to id
        mapping = {}
        for node in path[target]["nodes"]:
            if node["isDefense"] == True:
                # get all the defenses (classdefs) for the corresponding class object
                classdefs = metadata["assets"][node["class"]]["defenses"]
                # find info for one defense from classdefs.
                for d in classdefs:
                    # name of that particular defense = attackstep value for the path node
                    if d["name"] == node["attackstep"]:
                        if "suppress" not in d["tags"]:
                            mapping[node["index"]] = node["id"]
                            continue
            else:
                mapping[node["index"]] = node["id"]
        # transform edges from index to id
        edges_by_ids = []
        for edge in edges_by_indices:
            # only if both the nodes in edges are in mapping dict then append those edges in edges_by_ids
            if mapping.get(edge[0],False) and mapping.get(edge[1],False):
                edges_by_ids.append((mapping[edge[0]], mapping[edge[1]]))
        self.add_edges_from(edges_by_ids)
        for node in path[target]["nodes"]:
            # only those nodes which are mapped that means are nor suppressed
            if mapping.get(node["index"],False):
                # as name field is given as example - (32) Given Name; and we only need the "Given Name"
                temp = node["name"]
                object_name = temp[temp.index(' ')+1:]
                self.nodes[node["id"]]["id"] = node["id"]
                self.nodes[node["id"]]["index"] = node["index"]
                self.nodes[node["id"]]["eid"] = node["eid"]
                self.nodes[node["id"]]["name"] = object_name
                self.nodes[node["id"]]["class"] = node["class"]
                self.nodes[node["id"]]["attackstep"] = node["attackstep"]
                self.nodes[node["id"]]["frequency"] = node["frequency"]
                self.nodes[node["id"]]["isDefense"] = node["isDefense"]
                self.nodes[node["id"]]["ttc"] = node["ttc"]
        logging.debug("Loaded the following graph nodes from json:\n" +
            str(self.nodes))

    def find_critical_attack_step(self, metric):
        logging.debug("Find critical attack step")
        node_metrics = {}
        match metric:
            case 'frequency':
                for node in self.nodes:
                    if not self.nodes[node]["isDefense"]:
                        node_metrics[node] = self.nodes[node]["frequency"]
                        logging.debug(f'Node:{self.nodes[node]["id"]} ' +
                            f'frequency:{self.nodes[node]["frequency"]}')

            case 'weighted_out_degrees':
                weighted_out_degrees = {node: \
                    [sum([self.nodes[child]["frequency"] \
                    for child in self.successors(node)])] \
                    for node in self.nodes}
                node_metrics = weighted_out_degrees

            case _:
                logging.error('find_critical_attack_step was given ' +
                    f'unkwnown metric: {metric}')
                return -1

        self.nodes_sorted = sorted(node_metrics,
            key=lambda key: (node_metrics[key]), reverse=True)

        # assigning scores high to low on nodes according to the sorted order
        score = len(self.nodes_sorted)
        metric_of_previous_node = None
        for node in self.nodes_sorted:
            if metric_of_previous_node is None:
                # score is being assigned to the most critical attack step
                self.nodes[node]["crit_score"] = score
            else:
                if node_metrics[node] == metric_of_previous_node:
                    # the metric of this node is the same as the previous one, so it will get the same criticality score
                    self.nodes[node]["crit_score"] = score
                else:
                    self.nodes[node]["crit_score"] = score - 1
                    score -= 1
            metric_of_previous_node = node_metrics[node]

        logging.debug('Sorted nodes with criticality scores:')
        for node in self.nodes_sorted:
            logging.debug(f'{self.nodes[node]["id"]}\t' +
                f'{self.nodes[node]["crit_score"]}')
        return 0


    def find_best_defense(self, meta_lang, model_dict_list,
        budget_remaining, resultsfile):
        data = read_json_file(resultsfile)

        def_cost_list_dict={}
        for top_attack_step in self.nodes_sorted:
            block_range_def = {}
            no_of_def_for_i_node = 0
            pred_nodes = []
            logging.debug(f"Analyzing attack step {top_attack_step} to " +
                "find suitable defense")
            for pred_node in self.predecessors(top_attack_step):
                pred_nodes.append(pred_node)
                if self.nodes[pred_node]["isDefense"]:
                    no_of_def_for_i_node += 1
                    block_range_def[pred_node] = sum([self.nodes[child]["frequency"] for child in self.successors(pred_node)])

            if no_of_def_for_i_node > 0:
                for no_def in range(no_of_def_for_i_node):
                    best_def = max(block_range_def, key=block_range_def.get)
                    logging.debug(f"Best defence candidate: {best_def}")
                    not_enough_budget = False
                    for node in self.nodes:
                        if self.nodes[node]["id"] == best_def:

                            # Checking for user specified cost tags
                            for idx, model_dict in enumerate(model_dict_list):
                                if self.nodes[node]["eid"] == model_dict["exportedId"]:
                                    def_costs = model_dict["attributesJsonString"]

                                    cost_mc=[]

                                    this_cost_mc = None

                                    # Check all tags associated to the defense
                                    for key in def_costs:
                                        # If the tag has the same name of the defense
                                        if self.nodes[node]["attackstep"] == key[:-3]:
                                            # If the tag ends with "_mc"
                                            if key[-3:] == '_mc':
                                                cost_mc = def_costs[key].split(" ")
                                                if len(cost_mc) > 1:
                                                    this_cost_mc = cost_mc.pop(0)
                                                    new_cost_mc_list = " ".join(cost_mc)
                                                    model_dict_list[idx]["attributesJsonString"][key] = new_cost_mc_list
                                                else:
                                                    this_cost_mc = cost_mc[0]
                                                    model_dict_list[idx]["attributesJsonString"][key] = [this_cost_mc]
                                                logging.debug("Found user defined monetary cost" +
                                                    " tag updating defence values to:\n" +
                                                    model_dict_list[idx]["attributesJsonString"][key])

                                        if this_cost_mc:
                                            monetary_cost = json.dumps(this_cost_mc)

                                            if budget_remaining > int(this_cost_mc):
                                                changed_budget = budget_remaining - int(this_cost_mc)
                                                data["CoAs"].append({})
                                                data["CoAs"][-1]["monetary_cost"] = {"1": int(this_cost_mc)}

                                                data["CoAs"][-1]["defenses"] = []
                                                if len(data["CoAs"]) > 1:
                                                    data["CoAs"][-1]["defenses"] = data["CoAs"][-2]["defenses"].copy()
                                                data["CoAs"][-1]["defenses"].append({"ref": def_costs["ref"], "defenseName":  key[:-3], "defenseInfo":  key[:-3] + " is used"})
                                                self.nodes[node]["ref"] = def_costs["ref"]

                                                write_json_file(resultsfile, data)

                                                logging.debug("Defence fits into the budget " +
                                                    "and therefore can be applied");
                                                return self.nodes[node], changed_budget
                                            else:
                                                not_enough_budget = True
                                                logging.debug("Defence is beyond the budget " +
                                                    "and therefore cannot be applied");
                                                block_range_def[best_def] = 0  # if both costs are high or no cost given
                                                break

                                if not_enough_budget:
                                    break
                            if not_enough_budget:
                                break

                            classdefs = meta_lang["assets"][self.nodes[node]["class"]]["defenses"]
                            defense_info = next((d for d in classdefs if d["name"] == self.nodes[node]["attackstep"]), False)
                            if "cost" not in defense_info["metaInfo"]:
                                logging.info('No user defined tag or ' +
                                    'language cost was found for the ' +
                                    f'{defense_info["name"]} defence');
                                break

                            def_class_cost = defense_info["metaInfo"]["cost"]
                            def_name = defense_info["name"]
                            current_mc = None

                            if len(def_class_cost) > 1:
                                current_mc = def_class_cost.pop(0)
                            else:
                                current_mc = def_class_cost[0]

                            if budget_remaining > current_mc:
                                changed_budget = budget_remaining - current_mc
                                monetary_cost = json.dumps(current_mc)
                                results = '"Monetary Cost of defense is: " {} \n'.format(monetary_cost)

                                data["CoAs"].append({})
                                data["CoAs"][-1]["monetary_cost"] = {"1": int(current_mc)}

                                data["CoAs"][-1]["defenses"] = []
                                if len(data["CoAs"]) > 1:
                                    data["CoAs"][-1]["defenses"] = data["CoAs"][-2]["defenses"].copy()
                                data["CoAs"][-1]["defenses"].append({"ref": def_costs["ref"], "defenseName": def_name, "defenseInfo": def_name + " is used" })
                                self.nodes[node]["ref"] = def_costs["ref"]

                                write_json_file(resultsfile, data)


                                results = '"Name of defense is: " {} \n'.format(def_name)
                                logging.debug("Defence fits into the budget " +
                                        "and therefore can be applied");
                                return self.nodes[node], changed_budget
                            else:
                                not_enough_budget = True
                                block_range_def[best_def] = 0  # if both costs are high or no cost given
                                logging.debug("Defence is beyond the budget " +
                                    "and therefore cannot be applied");
                                break

                            logging.info('No user defined tag or ' +
                                'language cost was found for the ' +
                                f'{defense_info["name"]} defence');
                        if not_enough_budget:
                        #TODO when the defense is out of budget wrt
                        # top_attack_step (can be improved - once a defense out
                        # of budget it should be removed totally)
                            break
                    block_range_def[best_def] = 0  # if both costs are high or no cost given
            else:
                logging.info("No defence was available for Attack step:" +
                    f"{top_attack_step}")
        logging.warning("No defence was available for any of the " +
            "attack steps.")
        return None, None


def merge_attack_graphs(graphs):
    res = AttackGraph()
    freq_of_i = {}
    logging.debug(f"Merge {len(graphs)} attack graphs.")
    for i in range(len(graphs)):
        for node in graphs[i].nodes:
            if node in res.nodes:
                freq_of_i[node] = res.nodes[node]["frequency"]
            else:
                freq_of_i[node] = 0
        res = nx.algorithms.operators.binary.compose(res, graphs[i])
        for node in graphs[i].nodes:
            res.nodes[node]["frequency"] = freq_of_i[node] + graphs[i].nodes[node]["frequency"]
    logging.debug(f"Attack graphs merger result:\n" + str(res.nodes))
    return res

