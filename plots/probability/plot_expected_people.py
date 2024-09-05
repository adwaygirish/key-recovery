import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np
import yaml
import time
import math

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
    with open('config_expected_people.yaml', 'r') as file:
        data = yaml.safe_load(file)

    relative_path = data['Folder']
    y_labels = data['YLabels']
    epsilon = data['Epsilon']
    total_runs = data['Iterations']
    h_line = data['HLine']
    v_line = data['VLine']
    output_folder = data['OutputFolder']

    relevant_directories, relevant_numbers = GetDirectories(relative_path)

    for key, value in (data['Data']).items():
        plot(relevant_directories=relevant_directories,
             varying=key, 
             relevant_dirname=value['RelevantDir'], 
             relevant_elements=value['RelevantElements'],
             total_runs=total_runs,
             y_labels=y_labels, 
             x_label=value['XLabel'], 
             h_line=h_line, 
             v_line=v_line, 
             output_folder=output_folder)

# This will plot with the varying parameter
# This will generate plots for both the trustees and people
def plot(relevant_directories, 
         varying, 
         relevant_dirname, 
         relevant_elements, 
         total_runs, 
         y_labels, 
         x_label,
         h_line,
         v_line, 
         output_folder):
    output_path = "./" + output_folder + "/" + varying + "/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    # In this function, we plot only the ones with varying parameter
    plotFiles = {}
    filenames = []
    no_of_trustees = {}
    for relevant_directory in relevant_directories:
        if not (relevant_dirname in relevant_directory):
            continue
        filenames = listFiles(relevant_directory)
        for filename in filenames:
            data = extractStringData(filename)
            plotFiles[data[varying]] = os.path.join(relevant_directory, filename)
            no_of_trustees[data[varying]] = data['Trustees']
    
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
        # result_trustees[len(result_trustees)-1] = GenerateCDFData(result_trustees[len(result_trustees)-1])
        for i in range(len(data_2.keys())):
            result_people[len(result_people)-1].append(data_2[i+1])
        # result_people[len(result_people)-1] = GenerateCDFData(result_people[len(result_people)-1])
    
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

    expected_contacts = {}
    expected_trustees = {}
    std_contacts = {}
    std_trustees = {}

    min_contacts = {}
    max_contacts = {}

    min_trustees = {}
    max_trustees = {}
    for ind, normalized_result in enumerate(normalized_result_people):
        expected = 0
        for i, prob in enumerate(normalized_result):
            expected += (i+1) * prob
            # Minimum of people to be contacted for recovering the key
            if i != len(normalized_result)-1 and parameters[ind] not in min_contacts:
                if prob == 0.0 and normalized_result[i+1] != 0:
                    min_contacts[parameters[ind]] = (i+2)
        # print(int(expected), max_contacts[parameters[ind]])
        expected_contacts[parameters[ind]] = int(expected)
        std_contacts[parameters[ind]] = GetStandardDeviation(normalized_result)
        min_contacts[parameters[ind]] = int(expected) - min_contacts[parameters[ind]]

        reversed_normalized_result = normalized_result[::-1]
        # Maximum number of people that should be contacted for recovering the key
        for i, prob in enumerate((reversed_normalized_result)):
            if parameters[ind] in max_contacts:
                break
            if i == 0 and prob != 0.0:
                max_contacts[parameters[ind]] = len(reversed_normalized_result)
                break
            else:
                # print(prob, i)
                if prob == 0.0 and reversed_normalized_result[i+1] != 0:
                    max_contacts[parameters[ind]] = len(reversed_normalized_result) - (i+1)
        max_contacts[parameters[ind]] = max_contacts[parameters[ind]] - int(expected)

    for ind, normalized_result in enumerate(normalized_result_trustees[:no_of_trustees[parameters[ind]]]):
        # print(no_of_trustees[parameters[ind]])
        expected = 0
        for i, prob in enumerate(normalized_result):
            expected += (i+1) * prob
            if i != 0 and i != len(normalized_result)-1:
                if prob == 0.0 and normalized_result[i+1] != 0:
                    min_trustees[parameters[ind]] = (i+2)
                    # print(i+2)
                if prob != 0 and normalized_result[i+1] == 0.0:
                    max_trustees[parameters[ind]] = (i+1)
                    # print(i+1)
        if parameters[ind] not in max_trustees:
            max_trustees[parameters[ind]] = no_of_trustees[parameters[ind]]
        expected_trustees[parameters[ind]] = int(expected)
        std_trustees[parameters[ind]] = GetStandardDeviation(normalized_result)
        min_trustees[parameters[ind]] = int(expected) - min_trustees[parameters[ind]]
        max_trustees[parameters[ind]] = max_trustees[parameters[ind]] - int(expected)

    # print(max_trustees, min_trustees)

    relevant_indices = [parameters.index(r) for r in relevant_elements]
    bar_width = 4

    errors = [list(min_trustees.values()), list(max_trustees.values())]

    # Plot the graph for number of trustees for all the parameter levels
    # for i in relevant_indices:
    plt.bar(parameters, list(expected_trustees.values()), yerr=list(std_trustees.values()),
            capsize=5, width=bar_width, color='skyblue', edgecolor='black')
    # Set labels and title
    plt.xlabel(x_label, fontsize=21)
    plt.ylabel(y_labels[1], fontsize=21)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    # plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
    plt.ylim(bottom=0)

    output_filename = output_path + '/plot-expected-people-' + varying + '-tr-std.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # Plot the bar graph with standard deviation as the error bars
    plt.bar(parameters, list(expected_contacts.values()), yerr=list(std_contacts.values()),
            capsize=5, width=bar_width, color='skyblue', edgecolor='black')
    # Set labels and title
    plt.xlabel(x_label, fontsize=21)
    plt.ylabel(y_labels[0], fontsize=21)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)
    # plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
    plt.ylim(bottom=0)

    output_filename = output_path + '/plot-expected-people-' + varying + '-anon-std.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # errors = [list(min_contacts.values()), list(max_contacts.values())]

    # Plot the bar graph with error bars representing the minimum and maximum
    # number of people to be contacted for recovery
    # Plot the bar graph with standard deviation as the error bars
    
    # plt.bar(parameters, list(expected_contacts.values()), yerr=errors,
    #         capsize=5, width=bar_width, color='skyblue', edgecolor='black')
    # # Set labels and title
    # plt.xlabel(x_labels[1], fontsize=21)
    # if varying == 'Anonymity':
    #     plt.ylabel(y_label, fontsize=21)
    # plt.xticks(fontsize=18)
    # plt.yticks(fontsize=18)
    # # plt.legend(title=legend_title, fontsize='xx-large', title_fontsize='xx-large')
    # plt.ylim(bottom=0)

    # output_filename = output_path + '/plot-expected-' + varying + '-anon-min-max.pdf'
    # plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    # plt.cla()

def GetStandardDeviation(prob_list):
    e_x2 = 0
    e_x = 0
    for i, prob in enumerate(prob_list):
        e_x += (i+1) * prob
        e_x2 += (i+1) * (i+1) * prob

    std = math.sqrt(e_x2 - e_x * e_x)

    return int(std)


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