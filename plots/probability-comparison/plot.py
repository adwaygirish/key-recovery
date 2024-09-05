import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np
import yaml
import time

plt.style.use(
        {
            'axes.spines.left': True,
            'axes.spines.bottom': True,
            'axes.spines.top': True,
            'axes.spines.right': True,
            'xtick.bottom': True,
            'ytick.left': True,
            'axes.grid': True,
            'grid.linestyle': ':',
            'grid.linewidth': 0.5,
            'grid.alpha': 0.5,
            'grid.color': 'k',
            'axes.edgecolor': 'k',
            'axes.linewidth': 0.5
        }        
)

class Data:
    def __init__(self, p1, p2, p3, p4):
        self.p1 = p1
        self.p2 = p2
        self.p3 = p3
        self.p4 = p4

    def __eq__(self, other):
        return (self.p1, self.p2, self.p3, self.p4) == (other.p1, other.p2, other.p3, other.p4)

    def __hash__(self):
        return hash((self.p1, self.p2, self.p3, self.p4))

# use serif font
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']
plt.figure(figsize=(5,4))

def main():
    # Load YAML file
    with open('config.yaml', 'r') as file:
        data = yaml.safe_load(file)

    relative_path = data['Folder']
    y_label = data['YLabel']
    x_labels = data['XLabels']
    total_runs = data['Iterations']
    output_folder = data['OutputFolder']
    colors = data['Colors']

    relevant_directories, _ = GetDirectories(relative_path)

    for key, value in (data['Data']).items():
        plot(relevant_directories=relevant_directories,
             colors=colors,
             varying=key, 
             relevant_dirname=value['RelevantDir'], 
             total_runs=total_runs,
             y_label=y_label, 
             x_labels=x_labels, 
             output_folder=output_folder,
             obtain_probabilities=value['Obtained'],
             whistleblow_probabilities=value['Whistleblow'],
             memories=value['Memory'],
             memories_overall=value['MemoryOverall'])

def plot(relevant_directories,
         colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities,
         memories,
         memories_overall):
    plot_overall(relevant_directories,
        colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities)
    plot_memory_overall(relevant_directories,
        colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities,
         memories_overall)
    plot_memory(relevant_directories,
        colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         memories)
    plot_obtain(relevant_directories,
                colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         memories)
    plot_whistleblow(relevant_directories,
                     colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities)
    plot_obtain_whistleblow(relevant_directories,
                            colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities)
    plot_error_whistleblow(relevant_directories,
                            colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities)

# This function generates plots for random approaches
def plot_overall(relevant_directories,
                 colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities):
    output_path = "./" + output_folder + "/" + varying + "/" + "overall/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        filedata = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for key, value in filenamesMap.items():
            if key.p1 == 0 and key.p2 == 0:
                relevantFilenames.append(value)
                relevantFullnames.append(os.path.join(relevant_directory, value))
                relevantFiledata.append(key)
                trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]

        for data in relevantFiledata:
            if data.p4 == 0 and data.p3 in obtain_probabilities:
                for key, value in normalized_result_people.items():
                    if key.p3 == 100 and key.p4 == 0:
                        x_vals = [i+1 for i in range(len(value))]
                        plt.plot(x_vals, value, label='User' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), linestyle='-', linewidth=1.5)
                plotData = {}
                # plotData.append[normalized_result_people[data]]
                for d in relevantFiledata:
                    if data.p3 == d.p3 and (d.p4 == 1 or d.p4 == 0) and d.p3 in obtain_probabilities:
                        plotData[d.p4] = normalized_result_people[d]
                
                
                for key in [0, 1]:
                    value = plotData[key]
                    x_vals = [i+1 for i in range(len(value))]
                    plt.plot(x_vals, value, label='Adv' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), linestyle='-', linewidth=1.5)                

                # # Set labels and title
                plt.xlabel(x_labels[1], fontsize=21)
                if varying == 'Anonymity':
                    plt.ylabel(y_label, fontsize=21)
                plt.xticks(fontsize=18)
                plt.yticks(fontsize=18)
                plt.legend(fontsize='xx-large')
                plt.ylim(bottom=0)
                
                output_filename = output_path + '/plot-prob-cdf-' + str(data.p3) + '.pdf'
                plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
                plt.cla()

def plot_whistleblow(relevant_directories,
                     colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities):
    output_path = "./" + output_folder + "/" + varying + "/" + "whistleblow/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    
    count = 1

    labels = ['User', 'Risk-free Adversary']
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        filedata = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for key, value in filenamesMap.items():
            if key.p1 == 0 and key.p2 == 0:
                relevantFilenames.append(value)
                relevantFullnames.append(os.path.join(relevant_directory, value))
                relevantFiledata.append(key)
                trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]

        for data in relevantFiledata:
            if data.p4 == 0 and data.p3 in obtain_probabilities:
                for key, value in normalized_result_people.items():
                    if key.p3 == 100 and key.p4 == 0:
                        x_vals = [i+1 for i in range(len(value))]
                        plt.plot(x_vals, value, label='User' + "-", linestyle='-', linewidth=1.5)
                plotData = {}
                # plotData.append[normalized_result_people[data]]
                for d in relevantFiledata:
                    if data.p3 == d.p3 and d.p4 in whistleblow_probabilities and d.p3 in obtain_probabilities:
                        plotData[d.p4] = normalized_result_people[d]
                
                
                for key in whistleblow_probabilities:
                    value = plotData[key]
                    x_vals = [i+1 for i in range(len(value))]
                    plt.plot(x_vals, value, label='Adv'  + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), linestyle='-', linewidth=1.5)                

                # # Set labels and title
                plt.xlabel(x_labels[1], fontsize=21)
                if varying == 'Anonymity':
                    plt.ylabel(y_label, fontsize=21)
                plt.xticks(fontsize=18)
                plt.yticks(fontsize=18)
                plt.legend(fontsize='xx-large')
                plt.ylim(bottom=0)
                
                output_filename = output_path + '/plot-prob-cdf-' + str(data.p3) + '.pdf'
                plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
                plt.cla()

# This plot generates plots with memory of the user and the adversary
def plot_memory_overall(relevant_directories,
                        colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities,
         memories_overall):
    output_path = "./" + output_folder + "/" + varying + "/" + "memory-overall/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    
    count = 1

    labels = ['User', 'Risk-free Adversary']
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for memory_overall in memories_overall:
            for key, value in filenamesMap.items():
                if key.p1 == memory_overall and key.p2 == memory_overall:
                    relevantFilenames.append(value)
                    relevantFullnames.append(os.path.join(relevant_directory, value))
                    relevantFiledata.append(key)
                    trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]
        
        for memory_overall in memories_overall:
            if memory_overall > 25:
                continue
            for data in relevantFiledata:
                if data.p1 == memory_overall and data.p4 == 0 and data.p3 in obtain_probabilities:
                    for key, value in normalized_result_people.items():
                        if key.p1 == memory_overall and key.p3 == 100 and key.p4 == 0:
                            x_vals = [i+1 for i in range(len(value))]
                            plt.plot(x_vals, value, label='User' + "-" + str(key.p1) + "-" + str(key.p3) + "-" + str(key.p4), linestyle='-', linewidth=1.5)
                            
                    plotData = {}
                    # plotData.append[normalized_result_people[data]]
                    for d in relevantFiledata:
                        if d.p1 == 2 * memory_overall and data.p3 == d.p3 and d.p4 in [0, 1] and d.p3 in obtain_probabilities:
                            plotData[d.p4] = normalized_result_people[d]
                    
                    
                    for key in [0, 1]:
                        value = plotData[key]
                        x_vals = [i+1 for i in range(len(value))]
                        plt.plot(x_vals, value, label='Adv' + "-" + str(2*data.p1) + "-" + str(data.p3) + "-" + str(key), linestyle='-', linewidth=1.5)                

                    # # Set labels and title
                    plt.xlabel(x_labels[1], fontsize=21)
                    if varying == 'Anonymity':
                        plt.ylabel(y_label, fontsize=21)
                    plt.xticks(fontsize=18)
                    plt.yticks(fontsize=18)
                    plt.legend(fontsize='xx-large')
                    plt.ylim(bottom=0)
                    
                    output_filename = output_path + '/plot-prob-cdf-' + str(data.p1) + '-' + str(data.p3) + '.pdf'
                    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
                    plt.cla()

# This plot shows the difference in memory
def plot_memory(relevant_directories,
                colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         memories):
    output_path = "./" + output_folder + "/" + varying + "/" + "memory/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    
    count = 1

    labels = ['User', 'Risk-free Adversary']

    memories.sort()
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        filedata = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for key, value in filenamesMap.items():
            if (key.p1 in memories or key.p1 == 0) and key.p3 == 100 and key.p4 == 0:
                relevantFilenames.append(value)
                relevantFullnames.append(os.path.join(relevant_directory, value))
                relevantFiledata.append(key)
                trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]

        for ind, memory in enumerate(memories):
            for data in relevantFiledata:
                if memory == data.p1:
                    x_vals = [i for i in range(len(normalized_result_people[data]))]
                    value = normalized_result_people[data]
                    plt.plot(x_vals, value, label=str(data.p1), color=colors[ind], linestyle='-', linewidth=1.5)

        for data in relevantFiledata:
            if data.p1 == 0:
                value = normalized_result_people[data]
                x_vals = [i for i in range(len(normalized_result_people[data]))]
                plt.plot(x_vals, value, label='Random', color=colors[len(colors) - 1], linestyle=':', linewidth=5)         

        # # Set labels and title
        plt.xlabel(x_labels[1], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(title='Memory Error', fontsize='xx-large', title_fontsize='xx-large', loc='center left', bbox_to_anchor=(1, 0.5))
        plt.ylim(bottom=0)
        
        output_filename = output_path + '/plot-prob-cdf-memory.pdf'
        plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
        plt.cla()

# This plot shows the difference in obtaining the secret
def plot_obtain(relevant_directories,
                colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         memories):
    output_path = "./" + output_folder + "/" + varying + "/" + "obtain/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    
    memories.append(0)
    memories.sort()
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        filedata = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for key, value in filenamesMap.items():
            if (key.p1 in memories) and key.p3 in obtain_probabilities and key.p4 == 0:
                relevantFilenames.append(value)
                relevantFullnames.append(os.path.join(relevant_directory, value))
                relevantFiledata.append(key)
                trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]
        
        for memory in memories:
            for obtain in obtain_probabilities:
                    for d in relevantFiledata:
                        if d.p1 == memory and d.p3 == obtain:
                            value = normalized_result_people[d]
                            x_vals = [i+1 for i in range(len(value))]
                            plt.plot(x_vals, value, label=str(obtain), linewidth=1.5)               

            # # Set labels and title
            plt.xlabel(x_labels[1], fontsize=21)
            if varying == 'Anonymity':
                plt.ylabel(y_label, fontsize=21)
            plt.xticks(fontsize=18)
            plt.yticks(fontsize=18)
            plt.legend(title='Obtaining \n probability', fontsize='xx-large', title_fontsize='xx-large', loc='best')
            plt.ylim(bottom=0)
            
            output_filename = output_path + '/plot-prob-cdf-' + str(memory) + '.pdf'
            plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
            plt.cla()

def plot_obtain_whistleblow(relevant_directories,
                            colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities):
    output_path = "./" + output_folder + "/" + varying + "/" + "obtain-wb/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)

    obtain_probabilities = [80, 70]
    whistleblow_probabilities = [0, 1, 2]
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        filedata = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for key, value in filenamesMap.items():
            if (key.p1 == 40 and key.p2 == 40 and key.p3 in obtain_probabilities and key.p4 in whistleblow_probabilities) or (key.p1 == 20 and key.p2 == 20 and key.p3 == 100 and key.p4 == 0):
                relevantFilenames.append(value)
                relevantFullnames.append(os.path.join(relevant_directory, value))
                relevantFiledata.append(key)
                trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]

        print(len(relevantFiledata))

        for r in relevantFiledata:
            print(r.p3, r.p4)
        
        colorCount = 1
        colorDict = {}

        for data in relevantFiledata:
            if data.p4 == 0 and data.p1 == 20:
                for key, value in normalized_result_people.items():
                    if key.p3 == 100 and key.p4 == 0:
                        x_vals = [i+1 for i in range(len(value))]
                        plt.plot(x_vals, value, label='User' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[0], linestyle='-', linewidth=1.5)
        # plotData.append[normalized_result_people[data]]
        for per in [80, 70]:
            for indc, data in enumerate(relevantFiledata):
                if data.p1 == 40 and data.p4 == 0 and data.p3 == per:
                    x_vals = [i+1 for i in range(len(normalized_result_people[data]))]
                    plt.plot(x_vals, normalized_result_people[data], label='Adv' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[colorCount], linestyle='-', linewidth=1.5)
                    colorDict[data.p3] = colorCount
                    colorCount = colorCount + 1 

        colorCount = 1
        for per in [80, 70]:
            for indc, data in enumerate(relevantFiledata):
                if data.p1 == 40 and data.p4 == 1 and data.p3 == per:
                    x_vals = [i+1 for i in range(len(normalized_result_people[data]))]
                    plt.plot(x_vals, normalized_result_people[data], label='Adv' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[colorDict[data.p3]], linestyle='--', linewidth=1.5)
        
        for per in [80, 70]:
            for indc, data in enumerate(relevantFiledata):
                if data.p1 == 40 and data.p4 == 2 and data.p3 == per:
                    x_vals = [i+1 for i in range(len(normalized_result_people[data]))]
                    plt.plot(x_vals, normalized_result_people[data], label='Adv' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[colorDict[data.p3]], linestyle=':', linewidth=1.5)

        # # Set labels and title
        plt.xlabel(x_labels[1], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(fontsize='xx-large', loc='center left', bbox_to_anchor=(1, 0.5))
        # legend = plt.legend(fontsize='xx-large', loc='upper center', bbox_to_anchor=(0.5, 1.30), ncol=3, frameon=True)
        # legend.get_frame().set_facecolor('white')
        # legend.get_frame().set_edgecolor('black')
        plt.ylim(bottom=0)
        
        output_filename = output_path + '/plot-prob-cdf-obtain-wb' + '.pdf'
        plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
        plt.cla()

def plot_error_whistleblow(relevant_directories,
                            colors,
         varying,
         relevant_dirname,
         total_runs,
         y_label,
         x_labels,
         output_folder,
         obtain_probabilities,
         whistleblow_probabilities):
    output_path = "./" + output_folder + "/" + varying + "/" + "error-wb/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)

    memory_probabilities = [20, 40]
    whistleblow_probabilities = [0, 1]
    
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
    
        filenamesMap = {}
        filedata = {}
        for filename in filenames:
            _, data = extractStringData(filename)
            filenamesMap[data] = filename
            # fullnamesMap[data] = os.path.joim(relevant_directory, filename)

        relevantFilenames = []
        relevantFullnames = []
        relevantFiledata = []
        trackPlot = {}

        for key, value in filenamesMap.items():
            if (key.p1 in memory_probabilities and key.p3 == 50 and key.p4 in whistleblow_probabilities) or (key.p1 == 20 and key.p2 == 20 and key.p3 == 100 and key.p4 == 0):
                relevantFilenames.append(value)
                relevantFullnames.append(os.path.join(relevant_directory, value))
                relevantFiledata.append(key)
                trackPlot[key] = False

        result_maps_trustees = {}
        result_maps_people = {}
        for ind, data in enumerate(relevantFiledata):
            df = pd.read_csv(relevantFullnames[ind])

            column_number = df[df.columns[0]]
            column_trustees = df[df.columns[1]]
            column_people = df[df.columns[2]]
            temp_slice_tr = []
            temp_map_tr = dict(zip(column_number, column_trustees))
            for i in range(len(temp_map_tr.keys())):
                temp_slice_tr.append(temp_map_tr[i+1])
            temp_slice_tr = GenerateCDFData(temp_slice_tr)
            result_maps_trustees[data] = temp_slice_tr

            temp_slice_p = []
            temp_map_p = dict(zip(column_number, column_people))
            for i in range(len(temp_map_p.keys())):
                temp_slice_p.append(temp_map_p[i+1])
            temp_slice_p = GenerateCDFData(temp_slice_p)
            result_maps_people[data] = temp_slice_p
    
        # # Normalize the result based on the number of runs
        normalized_result_trustees = {}
        normalized_result_people = {}

        total_runs_val = total_runs

        for key, result in result_maps_trustees.items():
            normalized_result_trustees[key] = [x / total_runs_val for x in result]
        for key, result in result_maps_people.items():
            normalized_result_people[key] = [x / total_runs_val for x in result]

        print(len(relevantFiledata))

        for r in relevantFiledata:
            print(r.p3, r.p4)
        
        colorCount = 1
        colorDict = {}
        for data in relevantFiledata:
            if data.p4 == 0 and data.p1 == 20 and data.p2 == 20:
                
                x_vals = [i+1 for i in range(len(normalized_result_people[data]))]
                plt.plot(x_vals, normalized_result_people[data], label='User' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[0], linestyle='-', linewidth=1.5)
                break
        
        # plotData.append[normalized_result_people[data]]
        for per in memory_probabilities:
            for indc, data in enumerate(relevantFiledata):
                if data.p1 == per and data.p4 == 0 and data.p3 == 50:
                    x_vals = [i+1 for i in range(len(normalized_result_people[data]))]
                    plt.plot(x_vals, normalized_result_people[data], label='Adv' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[colorCount], linestyle='-', linewidth=1.5)
                    colorDict[data.p1] = colorCount
                    colorCount = colorCount + 1 

        colorCount = 1
        for per in memory_probabilities:
            for indc, data in enumerate(relevantFiledata):
                if data.p1 == per and data.p4 == 1 and data.p3 == 50:
                    x_vals = [i+1 for i in range(len(normalized_result_people[data]))]
                    plt.plot(x_vals, normalized_result_people[data], label='Adv' + "-" + str(data.p1) + "-" + str(data.p3) + "-" + str(data.p4), color=colors[colorDict[data.p1]], linestyle='--', linewidth=1.5)
                    colorCount = colorCount + 1


        # # Set labels and title
        plt.xlabel(x_labels[1], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(fontsize='xx-large', loc='center left', bbox_to_anchor=(1, 0.5))
        # legend = plt.legend(fontsize='xx-large', loc='upper center', bbox_to_anchor=(0.5, 1.30), ncol=3, frameon=True)
        # legend.get_frame().set_facecolor('white')
        # legend.get_frame().set_edgecolor('black')
        plt.ylim(bottom=0)
        
        output_filename = output_path + '/plot-prob-cdf-error-wb' + '.pdf'
        plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
        plt.cla()


def GenerateCDFData(data):
    sum_val = 0
    output = []
    for d in data:
        sum_val += d
        output.append(sum_val)
    return output

# Gives the directories
def GetDirectories(relative_path):
    path = os.path.join(os.getcwd(), relative_path)

    # Get the list of all files and directories in the current directory
    directories = os.listdir(path)

    relevant_directories = []
    relevant_numbers = []

    # Do not consider the numwise simulation
    for directory in directories:
        folder_path = os.path.join(path, directory)
        if ".DS_Store" in folder_path:
            continue
        dirs = os.listdir(folder_path)
        relevant_numbers.append(directory)
        for dir in dirs:
            if "num" in dir:
                continue
            else:
                relevant_folder_path = os.path.join(folder_path, dir)
                relevant_directories.append(relevant_folder_path)

    return relevant_directories, relevant_numbers

# This extracts data from the files without parameter in the subsecrets
def extractStringData(filename):
    # filename = 'result-probability-26-2-50-40-150-.csv'
    indices = [i for i, c in enumerate(filename) if c == '-']
    data = []
    output = {}
    for i in range(3,len(indices)):
        if i == len(indices) - 1:
            break
        else:
            data.append(int(filename[indices[i]+1:indices[i+1]]))
    output['Threshold'] = data[0]
    output['Trustees'] = data[1]
    output['Anonymity'] = data[2]
    output['Subsecrets'] = data[3]
    output['Absolute'] = data[4]
    if len(data) > 5:
        output['Percentage1'] = data[5]
        output['Percentage2'] = data[6]
        output['Percentage3'] = data[7]
        output['Percentage4'] = data[8]
    else:
        output['Percentage1'] = 0
        output['Percentage2'] = 0
        output['Percentage3'] = 0
        output['Percentage4'] = 0
    return output, Data(output['Percentage1'], output['Percentage2'],
                        output['Percentage3'], output['Percentage4'])

def extractStringData2(filename):
    # filename = 'result-probability-26-2-50-40-150-.csv'
    indices = [i for i, c in enumerate(filename) if c == '-']
    data = []
    output = {}
    for i in range(3,len(indices)):
        if i == len(indices) - 1:
            break
        else:
            data.append(int(filename[indices[i]+1:indices[i+1]]))
    output['Threshold'] = data[0]
    output['Trustees'] = data[1]
    output['Anonymity'] = data[2]
    output['Subsecrets'] = data[3]
    output['Absolute'] = data[4]
    return output

def listFiles(directory):
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

def all_directories_exist(path):
    # Check if the main directory exists
    if not os.path.exists(path):
        return False
    
    # Get a list of all directories in the path
    directories = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
    
    # Check if all directories exist
    for directory in directories:
        if not os.path.exists(os.path.join(path, directory)):
            return False
    
    return True

if __name__ == '__main__':
    main()