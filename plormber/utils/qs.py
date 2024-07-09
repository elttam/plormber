import urllib.parse as urlparse

class DictNode:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.parent = None


    def set_parent(self, parent):
        self.parent = parent


    def is_end_node(self):
        return not isinstance(self.value, dict)


    def to_str(self, depth=1) -> tuple[str, int]:
        k = "["+urlparse.quote_plus(self.key)+"]"
        if self.parent is None:
            k = urlparse.quote_plus(self.key)
        if self.is_end_node() and not isinstance(self.value, list):
            val = self.value
            if val is None:
                val = 'null'
            elif isinstance(val, bool):
                val = str(val).lower()
            k = k + '=' + urlparse.quote_plus(str(val))

        if self.parent is not None:
            parent_key, depth = self.parent.to_str(depth=depth+1)
            k = parent_key + k
        
        if self.is_end_node() and isinstance(self.value, list):
            temp_k = k
            ks = []
            for index, value in enumerate(self.value):
                ks.append(temp_k + "[" + str(index) + "]=" + urlparse.quote_plus(str(value)))

            k = "&".join(ks)

        return (k, depth)

        
class DictGraph:

    def __init__(self, d: dict):
        self.d = d
        self.end_nodes: list[DictNode] = []
        self.create_nodes()
        self.max_depth = 0


    def create_nodes(self):
        items = list(self.d.items())

        while len(items) > 0:
            stack = [(None, items.pop(0))]
            
            while len(stack) > 0:
                parent_node, key_val = stack.pop(0)
                k,v = key_val
                node = DictNode(k, v)
                if parent_node is not None:
                    node.set_parent(parent_node)

                if node.is_end_node():
                    self.end_nodes.append(node)
                else:
                    for child_k, child_v in v.items():
                        stack.insert(0, (node, (child_k, child_v)))


    def flatten_to_qs_list(self) -> list:
        result = []
        for end_node in self.end_nodes:
            key_path, depth = end_node.to_str()
            if depth > self.max_depth:
                self.max_depth = depth
            result.append(key_path)

        return result


def parse_dict_to_qs_string(d: dict) -> str:
    graph = DictGraph(d)
    return '&'.join(graph.flatten_to_qs_list())