import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np
import yaml
import time
import re

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
    epsilon = data['Epsilon']
    total_runs = data['Iterations']
    h_line = data['HLine']
    v_line = data['VLine']
    output_folder = data['OutputFolder']
    colors = data['Colors']

    relevant_directories, relevant_numbers = GetDirectories(relative_path)

    for key, value in (data['Data']).items():
        if value['Flag']:
            plot(relevant_directories=relevant_directories, 
                epsilon=epsilon, 
                varying=key, 
                relevant_dirname=value['RelevantDir'], 
                relevant_elements=value['RelevantElements'],
                legend_title=value['Legend'],
                total_runs=total_runs,
                y_label=y_label, 
                x_labels=x_labels, 
                h_line=h_line, 
                v_line=v_line, 
                output_folder=output_folder,
                colors=colors)
            plot_wo(relevant_directories=relevant_directories, 
                epsilon=epsilon, 
                varying=key, 
                relevant_dirname=value['RelevantDir'], 
                relevant_elements=value['RelevantElements'],
                legend_title=value['Legend'],
                total_runs=total_runs,
                y_label=y_label, 
                x_labels=x_labels, 
                h_line=h_line, 
                v_line=v_line, 
                output_folder=output_folder,
                colors=colors)
        else:
            plot_alternate(relevant_directories=relevant_directories, 
                epsilon=epsilon, 
                varying=key, 
                relevant_dirname=value['RelevantDir'], 
                relevant_elements=value['RelevantElements'],
                legend_title=value['Legend'],
                total_runs=total_runs,
                y_label=y_label, 
                x_labels=x_labels, 
                h_line=h_line, 
                v_line=v_line, 
                output_folder=output_folder,
                colors=colors)
            plot_wo(relevant_directories=relevant_directories, 
                epsilon=epsilon, 
                varying=key, 
                relevant_dirname=value['RelevantDir'], 
                relevant_elements=value['RelevantElements'],
                legend_title=value['Legend'],
                total_runs=total_runs,
                y_label=y_label, 
                x_labels=x_labels, 
                h_line=h_line, 
                v_line=v_line, 
                output_folder=output_folder,
                colors=colors)

# This will plot with the varying parameter
# This will generate plots for both the trustees and people
def plot(relevant_directories, 
         epsilon, 
         varying, 
         relevant_dirname, 
         relevant_elements, 
         legend_title,
         total_runs, 
         y_label, 
         x_labels,
         h_line,
         v_line, 
         output_folder,
         colors):
    output_path = "./" + output_folder + "/" + varying + "/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    # In this function, we plot only the ones with varying parameter
    # relevant_dirname = "csv-prob_add_v_th"
    plotFiles = {}
    bplotFiles = {}
    filenames = []
    bfilenames = []

    b_relevant_dirname = re.sub(r'-(.*?)-', '-baseline-', relevant_dirname)

    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
        for filename in filenames:
            data = extractStringData(filename)
            plotFiles[data[varying]] = os.path.join(relevant_directory, filename)

    for relevant_directory in relevant_directories:
        if not (b_relevant_dirname in relevant_directory):
            continue
        bfilenames = listFiles(relevant_directory)
        for bfilename in bfilenames:
            data = extractStringData(bfilename)
            bplotFiles[data[varying]] = os.path.join(relevant_directory, bfilename)
    
    parameters = list(plotFiles.keys())
    parameters.sort()
    print(parameters)
    
    result_maps_trustees = {}
    result_maps_people = {}
    b_result_maps_trustees = {}
    b_result_maps_people = {}
    result_trustees = []
    result_people = []
    b_result_trustees = []
    b_result_people = []

    for parameter in parameters:
        df = pd.read_csv(plotFiles[parameter])
        # print(plotFiles[parameter])
        # Create a dictionary mapping from two columns
        column_number = df[df.columns[0]]
        column_trustees = df[df.columns[1]]
        column_people = df[df.columns[2]]
        result_maps_trustees[parameter] = dict(zip(column_number, column_trustees))
        result_maps_people[parameter] = dict(zip(column_number, column_people))
    
    for parameter in parameters:
        df = pd.read_csv(bplotFiles[parameter])
        # print(plotFiles[parameter])
        # Create a dictionary mapping from two columns
        column_number = df[df.columns[0]]
        column_trustees = df[df.columns[1]]
        column_people = df[df.columns[2]]
        b_result_maps_trustees[parameter] = dict(zip(column_number, column_trustees))
        b_result_maps_people[parameter] = dict(zip(column_number, column_people))
    
    # Get the data for all the parameters and generate the CDF data
    for parameter in parameters:
        result_trustees.append([])
        result_people.append([])
        data_1 = result_maps_trustees[parameter]
        data_2 = result_maps_people[parameter]
        for i in range(len(data_1.keys())):
            result_trustees[len(result_trustees)-1].append(data_1[i+1])
        result_trustees[len(result_trustees)-1] = GenerateCDFData(result_trustees[len(result_trustees)-1])
        for i in range(len(data_2.keys())):
            result_people[len(result_people)-1].append(data_2[i+1])
        result_people[len(result_people)-1] = GenerateCDFData(result_people[len(result_people)-1])
    
    # Get the data for all the parameters and generate the CDF data
    for parameter in parameters:
        b_result_trustees.append([])
        b_result_people.append([])
        data_1 = b_result_maps_trustees[parameter]
        data_2 = b_result_maps_people[parameter]
        for i in range(len(data_1.keys())):
            b_result_trustees[len(b_result_trustees)-1].append(data_1[i+1])
        b_result_trustees[len(b_result_trustees)-1] = GenerateCDFData(b_result_trustees[len(b_result_trustees)-1])
        for i in range(len(data_2.keys())):
            b_result_people[len(b_result_people)-1].append(data_2[i+1])
        b_result_people[len(b_result_people)-1] = GenerateCDFData(b_result_people[len(b_result_people)-1])
    
    # Normalize the result based on the number of runs
    normalized_result_trustees = []
    normalized_result_people = []
    b_normalized_result_trustees = []
    b_normalized_result_people = []
    total_runs_val = total_runs
    for result in result_trustees:
        normalized_result_1 = [x / total_runs_val for x in result]
        normalized_result_trustees.append(normalized_result_1)
    for result in result_people:
        normalized_result_2 = [x / total_runs_val for x in result]
        normalized_result_people.append(normalized_result_2)
    
    for result in b_result_trustees:
        b_normalized_result_1 = [x / total_runs_val for x in result]
        b_normalized_result_trustees.append(b_normalized_result_1)
    for result in b_result_people:
        b_normalized_result_2 = [x / total_runs_val for x in result]
        b_normalized_result_people.append(b_normalized_result_2)

    relevant_indices = [parameters.index(r) for r in relevant_elements]

    # Plot the graph for number of trustees for all the parameter levels
    for ind, i in enumerate(relevant_indices):
        x_vals = [i+1 for i in range(len(normalized_result_trustees[i]))]
        plt.plot(x_vals, normalized_result_trustees[i], label=str(parameters[i]), color=colors[ind], linestyle='-', linewidth=1.5)
        plt.plot(x_vals, b_normalized_result_trustees[i], color=colors[ind], linestyle='--', linewidth=1.5)
        # Set labels and title
        plt.xlabel(x_labels[0], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)
    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-tr.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # Plot the graph for number of people for all the parameter levels
    for ind, i in enumerate(relevant_indices):
        # print(parameters[i])
        x_vals = [i+1 for i in range(len(normalized_result_people[i]))]
        plt.plot(x_vals, normalized_result_people[i], label=str(parameters[i]), color=colors[ind], linestyle='-', linewidth=1.5)
        plt.plot(x_vals, b_normalized_result_people[i], color=colors[ind], linestyle='--', linewidth=1.5)
        # print(normalized_result_people[i])

        # Set labels and title
        plt.xlabel(x_labels[1], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)

    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-anon.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

def plot_alternate(relevant_directories, 
         epsilon, 
         varying, 
         relevant_dirname, 
         relevant_elements, 
         legend_title,
         total_runs, 
         y_label, 
         x_labels,
         h_line,
         v_line, 
         output_folder,
         colors):
    output_path = "./" + output_folder + "/" + varying + "/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    # In this function, we plot only the ones with varying parameter
    # relevant_dirname = "csv-prob_add_v_th"
    plotFiles = {}
    filenames = []
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
        for filename in filenames:
            data = extractStringData(filename)
            plotFiles[data[varying]] = os.path.join(relevant_directory, filename)
    
    baselineData = extractStringData(filenames[0])
    b_relevant_dirname = "p-baseline-an"
    bplotFile = ""
    print(b_relevant_dirname)

    for relevant_directory in relevant_directories:
        if not (b_relevant_dirname in relevant_directory):
            continue
        bfilenames = listFiles(relevant_directory)
        for bfilename in bfilenames:
            data = extractStringData(bfilename)
            if data['Anonymity'] == baselineData['Anonymity']:
                bplotFile = os.path.join(relevant_directory, bfilename)

    df = pd.read_csv(bplotFile)
    # print(plotFiles[parameter])
    # Create a dictionary mapping from two columns
    b_column_number = df[df.columns[0]]
    b_column_trustees = df[df.columns[1]]
    b_column_people = df[df.columns[2]]
    b_result_map_trustees = dict(zip(b_column_number, b_column_trustees))
    b_result_map_people = dict(zip(b_column_number, b_column_people))
    b_result_trustees = []
    b_result_people = []
    for i in range(len(b_result_map_trustees.keys())):
        b_result_trustees.append(b_result_map_trustees[i+1])
    b_result_trustees = GenerateCDFData(b_result_trustees)

    for i in range(len(b_result_map_people.keys())):
        b_result_people.append(b_result_map_people[i+1])
    b_result_people = GenerateCDFData(b_result_people)
    
    parameters = list(plotFiles.keys())
    parameters.sort()
    print(parameters)
    
    result_maps_trustees = {}
    result_maps_people = {}
    result_trustees = []
    result_people = []

    for parameter in parameters:
        df = pd.read_csv(plotFiles[parameter])
        # print(plotFiles[parameter])
        # Create a dictionary mapping from two columns
        column_number = df[df.columns[0]]
        column_trustees = df[df.columns[1]]
        column_people = df[df.columns[2]]
        result_maps_trustees[parameter] = dict(zip(column_number, column_trustees))
        result_maps_people[parameter] = dict(zip(column_number, column_people))
    
    # print(result_maps_people)
    
    # Get the data for all the parameters and generate the CDF data
    for parameter in parameters:
        result_trustees.append([])
        result_people.append([])
        data_1 = result_maps_trustees[parameter]
        data_2 = result_maps_people[parameter]
        for i in range(len(data_1.keys())):
            result_trustees[len(result_trustees)-1].append(data_1[i+1])
        result_trustees[len(result_trustees)-1] = GenerateCDFData(result_trustees[len(result_trustees)-1])
        for i in range(len(data_2.keys())):
            result_people[len(result_people)-1].append(data_2[i+1])
        result_people[len(result_people)-1] = GenerateCDFData(result_people[len(result_people)-1])
    
    # Normalize the result based on the number of runs
    normalized_result_trustees = []
    normalized_result_people = []
    total_runs_val = total_runs
    for result in result_trustees:
        normalized_result_1 = [x / total_runs_val for x in result]
        normalized_result_trustees.append(normalized_result_1)
    for result in result_people:
        normalized_result_2 = [x / total_runs_val for x in result]
        normalized_result_people.append(normalized_result_2)
    
    b_normalized_result_trustees = [x / total_runs_val for x in b_result_trustees]
    b_normalized_result_people = [x / total_runs_val for x in b_result_people]

    relevant_indices = [parameters.index(r) for r in relevant_elements]

    # Plot the graph for number of trustees for all the parameter levels
    for i in relevant_indices:
        x_vals = [i+1 for i in range(len(normalized_result_trustees[i]))]
        plt.plot(x_vals, normalized_result_trustees[i], label=str(parameters[i]), color=colors[i], linestyle='-', linewidth=1.5)

    x_vals = [i+1 for i in range(len(b_normalized_result_trustees))]
    plt.plot(x_vals, b_normalized_result_trustees, label='Baseline', color=colors[len(relevant_indices)], linestyle='--', linewidth=1.5)
    # Set labels and title
    plt.xlabel(x_labels[0], fontsize=21)
    if varying == 'Anonymity':
        plt.ylabel(y_label, fontsize=21)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
    # plt.rc('text', usetex=True)
    plt.ylim(bottom=0)
    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-tr.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # Plot the graph for number of people for all the parameter levels
    for i in relevant_indices:
        # print(parameters[i])
        x_vals = [i+1 for i in range(len(normalized_result_people[i]))]
        plt.plot(x_vals, normalized_result_people[i], label=str(parameters[i]), color=colors[i], linestyle='-', linewidth=1.5)
        # print(normalized_result_people[i])

    x_vals = [i+1 for i in range(len(b_normalized_result_people))]
    plt.plot(x_vals, b_normalized_result_people, label='Baseline', color=colors[len(relevant_indices)], linestyle='--', linewidth=1.5)
    # Set labels and title
    plt.xlabel(x_labels[1], fontsize=21)
    if varying == 'Anonymity':
        plt.ylabel(y_label, fontsize=21)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
    # plt.rc('text', usetex=True)
    plt.ylim(bottom=0)

    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-anon.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

def plot_wo(relevant_directories, 
         epsilon, 
         varying, 
         relevant_dirname, 
         relevant_elements, 
         legend_title,
         total_runs, 
         y_label, 
         x_labels,
         h_line,
         v_line, 
         output_folder,
         colors):
    output_path = "./" + output_folder + "-wo/" + varying + "/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    # In this function, we plot only the ones with varying parameter
    # relevant_dirname = "csv-prob_add_v_th"
    plotFiles = {}
    filenames = []
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
        for filename in filenames:
            data = extractStringData(filename)
            plotFiles[data[varying]] = os.path.join(relevant_directory, filename)
    
    parameters = list(plotFiles.keys())
    parameters.sort()
    print(parameters)
    
    result_maps_trustees = {}
    result_maps_people = {}
    result_trustees = []
    result_people = []

    for parameter in parameters:
        df = pd.read_csv(plotFiles[parameter])
        # print(plotFiles[parameter])
        # Create a dictionary mapping from two columns
        column_number = df[df.columns[0]]
        column_trustees = df[df.columns[1]]
        column_people = df[df.columns[2]]
        result_maps_trustees[parameter] = dict(zip(column_number, column_trustees))
        result_maps_people[parameter] = dict(zip(column_number, column_people))
    
    # Get the data for all the parameters and generate the CDF data
    for parameter in parameters:
        result_trustees.append([])
        result_people.append([])
        data_1 = result_maps_trustees[parameter]
        data_2 = result_maps_people[parameter]
        for i in range(len(data_1.keys())):
            result_trustees[len(result_trustees)-1].append(data_1[i+1])
        result_trustees[len(result_trustees)-1] = GenerateCDFData(result_trustees[len(result_trustees)-1])
        for i in range(len(data_2.keys())):
            result_people[len(result_people)-1].append(data_2[i+1])
        result_people[len(result_people)-1] = GenerateCDFData(result_people[len(result_people)-1])
    
    # Normalize the result based on the number of runs
    normalized_result_trustees = []
    normalized_result_people = []
    total_runs_val = total_runs
    for result in result_trustees:
        normalized_result_1 = [x / total_runs_val for x in result]
        normalized_result_trustees.append(normalized_result_1)
    for result in result_people:
        normalized_result_2 = [x / total_runs_val for x in result]
        normalized_result_people.append(normalized_result_2)

    relevant_indices = [parameters.index(r) for r in relevant_elements]

    # Plot the graph for number of trustees for all the parameter levels
    for i in relevant_indices:
        x_vals = [i+1 for i in range(len(normalized_result_trustees[i]))]
        plt.plot(x_vals, normalized_result_trustees[i], label=str(parameters[i]), linestyle='-', linewidth=1.5)
        # Set labels and title
        plt.xlabel(x_labels[0], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)
    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-tr.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # Plot the graph for number of people for all the parameter levels
    for i in relevant_indices:
        # print(parameters[i])
        x_vals = [i+1 for i in range(len(normalized_result_people[i]))]
        plt.plot(x_vals, normalized_result_people[i], label=str(parameters[i]), linestyle='-', linewidth=1.5)
        # print(normalized_result_people[i])

        # Set labels and title
        plt.xlabel(x_labels[1], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)

    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-anon.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # Plot the graph for comparison of trustees and people
    for i in relevant_indices:
        x_vals = [i+1 for i in range(len(normalized_result_people[i]))]
        plt.plot(x_vals, normalized_result_trustees[i], label='Trustees', linestyle='-', linewidth=1.5)
        plt.plot(x_vals, normalized_result_people[i], label='People', linestyle='-', linewidth=1.5)

        # Set labels and title
        plt.xlabel(x_labels[2], fontsize=21)
        if varying == 'Anonymity':
            plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)

        if h_line:
            plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
            # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

        output_filename = output_path + '/plot-prob-cdf-th-' + varying + '-comp-' + str(parameters[i]) + '.pdf'
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