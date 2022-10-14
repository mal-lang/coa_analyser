from json_helpers import read_json_file, write_json_file
import json
import networkx as nx
import logging

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

    def apply_defense(self, node, budget, cost, data, asset_tags,
        defense_info, meta_lang, resultsfile):

        def_name = defense_info["name"]

        budget = budget - cost

        data["CoAs"].append({})
        data["CoAs"][-1]["monetary_cost"] = {"1": int(cost)}
        data["CoAs"][-1]["defenses"] = []
        if len(data["CoAs"]) > 1:
            data["CoAs"][-1]["defenses"] = data["CoAs"][-2]["defenses"].copy()
        data["CoAs"][-1]["defenses"].append({"ref": asset_tags["ref"],
            "defenseName": def_name,
            "assetName": self.nodes[node]["name"],
            "eid": self.nodes[node]["eid"],
            "defenseInfo": def_name + " is used" })
        self.nodes[node]["ref"] = asset_tags["ref"]
        defense_info["metaInfo"]["use_counter"] += 1

        write_json_file(resultsfile, data)

        logging.info(f'Defense {def_name} on {self.nodes[node]["name"]}' +
            f'(eid:{self.nodes[node]["eid"]}) with a cost of {cost} fit ' +
            'into the budget and was therefore applied.')
        return budget

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
                    logging.debug(f"Best defense candidate: {best_def}")
                    for node in self.nodes:
                        if self.nodes[node]["id"] == best_def:

                            costs_array = None

                            # Checking for user specified cost tags
                            for idx, model_dict in enumerate(model_dict_list):
                                asset_tags = None
                                if self.nodes[node]["eid"] == model_dict["exportedId"]:
                                    asset_tags = model_dict["attributesJsonString"]
                                    cost_tag_name = \
                                        self.nodes[node]["attackstep"] + '_mc'
                                    # If the tag has the same name of the defense
                                    if cost_tag_name in asset_tags:
                                        costs_array = asset_tags[cost_tag_name].split(" ")
                                        logging.debug('Found user defined ' +
                                            'monetary cost tag for ' +
                                            f'{self.nodes[node]["attackstep"]}' +
                                            f' on {self.nodes[node]["name"]}' +
                                            f'(eid:{self.nodes[node]["eid"]}):\n' +
                                            f'{costs_array}')
                                    break

                            if not asset_tags:
                                logging.warning('Failed to find asset in ' +
                                'the model dictionary with eid:' +
                                f'{self.nodes[node]["eid"]}.')
                                continue

                            classdefs = meta_lang["assets"][self.nodes[node]["class"]]["defenses"]
                            defense_info = next((d for d in classdefs if d["name"] == self.nodes[node]["attackstep"]), False)
                            # If there was no user defined tag containing the
                            # cost look for one in the language costs
                            if not costs_array and 'cost' in defense_info["metaInfo"]:
                                costs_array = defense_info["metaInfo"]["cost"]
                                logging.debug('Found language cost' +
                                    ' for defense ' +
                                    f'{defense_info["name"]}:\n' +
                                    f'{costs_array}')

                            if not costs_array:
                                logging.info('No user defined tag or ' +
                                    'language cost was found for the ' +
                                    f'{best_def} defense.')
                                break

                            if not "use_counter" in defense_info["metaInfo"]:
                                defense_info["metaInfo"]["use_counter"] = 0
                            use_counter = \
                                defense_info["metaInfo"]["use_counter"]
                            current_cost = int(costs_array[min(
                                len(costs_array) - 1, use_counter)])
                            logging.debug('Found the following costs_array ' +
                                'costs_array for ' +
                                f'{self.nodes[node]["attackstep"]} on ' +
                                f'on {self.nodes[node]["name"]}: ' +
                                f'{costs_array}, with a use counter of: ' +
                                f'{use_counter}, resulting in a cost of: ' +
                                f'{current_cost}')

                            if budget_remaining > current_cost:
                                return self.nodes[node], \
                                    self.apply_defense(node,
                                        budget_remaining, current_cost,
                                        data, asset_tags, defense_info,
                                        meta_lang, resultsfile)
                            else:
                                block_range_def[best_def] = 0  # if both costs are high or no cost given
                                logging.debug("Defense is beyond the budget " +
                                    "and therefore cannot be applied.")
                                break

                    block_range_def[best_def] = 0  # if both costs are high or no cost given
            else:
                logging.info("No defense was available for Attack step:" +
                    f"{top_attack_step}")
        logging.warning("No affordable defense was available for any of " +
            "the attack steps.")
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

