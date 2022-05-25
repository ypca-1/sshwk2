import pefile
import argparse
import os
import networkx
import re
import sys
from networkx.algorithms import bipartite
from networkx.drawing.nx_agraph import write_dot
import collections
import pprint

args = argparse.ArgumentParser("Visualize shared hostnames between a directory of malware samples")
args.add_argument("target_path", help="directory with malware samples")
args.add_argument("output_file", help="file to write DOT file to")
args.add_argument("malware_projection", help="file to write DOT file to")
args.add_argument("sectionname_projection", help="file to write DOT file to")
args = args.parse_args()

network = networkx.Graph()

for root, dirs, files in os.walk(args.target_path):
    for path in files:
        # see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root, path))
        except pefile.PEFormatError:
            continue
        fullpath = os.path.join(root, path)
        real_pe = pefile.PE(fullpath)

        if len(real_pe.sections):
            network.add_node(path, label=path[:32], color='black', penwidth=5, bipartite=0)
        for section in real_pe.sections:
            sname = str(section.Name, 'utf-8').strip()
            network.add_node(sname, label=sname, color='blue',
                             penwidth=10, bipartite=1)
            network.add_edge(sname, path, penwidth=2)
        if len(real_pe.sections):
            print("Extracted secction names from:", path)
            pprint.pprint(real_pe.sections)


write_dot(network, args.output_file)
malware = set(n for n, d in network.nodes(data=True) if d['bipartite'] == 0)
sectionname = set(network) - malware
malware_network = bipartite.projected_graph(network, malware)
sectionname_network = bipartite.projected_graph(network, sectionname)

write_dot(malware_network, args.malware_projection)
write_dot(sectionname_network, args.sectionname_projection)
