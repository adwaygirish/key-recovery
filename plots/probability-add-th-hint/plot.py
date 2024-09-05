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
    legend = data['Legend']
    output_folder = data['OutputFolder']
    line_styles = data['Linestyles']

    relevant_directories, relevant_numbers = GetDirectories(relative_path)

    for key, value in (data['Data']).items():
        plot(relevant_directories=relevant_directories, 
             epsilon=epsilon, 
             varying=key, 
             relevant_dirnames=value['RelevantDirs'], 
             parameter=value['Parameter'],
             legend_title=value['Legend'],
             total_runs=total_runs,
             y_label=y_label, 
             x_labels=x_labels, 
             h_line=h_line, 
             v_line=v_line,
             legend=legend,
             output_folder=output_folder,
             line_styles=line_styles)

# This will plot with the varying parameter
# This will generate plots for both the trustees and people
def plot(relevant_directories, 
         epsilon, 
         varying, 
         relevant_dirnames, 
         parameter, 
         legend_title,
         total_runs, 
         y_label, 
         x_labels,
         h_line,
         v_line,
         legend,
         output_folder,
         line_styles):
    output_path = "./" + output_folder + "/" + varying + "/"
    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    # In this function, we plot only the ones with varying parameter
    plotFiles = {}
    filenames = []
    for i, relevant_dirname in enumerate(relevant_dirnames):
        plotFiles[relevant_dirname] = {}
        for relevant_directory in relevant_directories:
            if relevant_dirname in relevant_directory and relevant_dirname + "t" not in relevant_directory:
                filenames = listFiles(relevant_directory)
                for filename in filenames:
                    data = extractStringData(filename, i)
                    if i == 1:
                        if data['SubsecretsThreshold'] == 80:
                            plotFiles[relevant_dirname][data[varying]] = os.path.join(relevant_directory, filename)
                    elif i == 2:
                        if data['Hints'] == 5:
                            plotFiles[relevant_dirname][data[varying]] = os.path.join(relevant_directory, filename)
                    else:
                        plotFiles[relevant_dirname][data[varying]] = os.path.join(relevant_directory, filename)
                break
    
    result_maps_trustees = [{} for i in range(len(relevant_dirnames))]
    result_maps_people = [{} for i in range(len(relevant_dirnames))]
    result_trustees = [[] for i in range(len(relevant_dirnames))]
    result_people = [[] for i in range(len(relevant_dirnames))]

    for i, relevant_dirname in enumerate(relevant_dirnames):
        df = pd.read_csv(plotFiles[relevant_dirname][parameter])
        column_number = df[df.columns[0]]
        column_trustees = df[df.columns[1]]
        column_people = df[df.columns[2]]
        result_maps_trustees[i][parameter] = dict(zip(column_number, column_trustees))
        result_maps_people[i][parameter] = dict(zip(column_number, column_people))
    
    # Get the data for all the parameters and generate the CDF data
    for i, relevant_dirname in enumerate(relevant_dirnames):
        result_trustees[i].append([])
        result_people[i].append([])
        data_1 = result_maps_trustees[i][parameter]
        data_2 = result_maps_people[i][parameter]
        for j in range(len(data_1.keys())):
            result_trustees[i][len(result_trustees[i])-1].append(data_1[j+1])
        result_trustees[i][len(result_trustees[i])-1] = GenerateCDFData(result_trustees[i][len(result_trustees[i])-1])
        for j in range(len(data_2.keys())):
            result_people[i][len(result_people[i])-1].append(data_2[j+1])
        result_people[i][len(result_people[i])-1] = GenerateCDFData(result_people[i][len(result_people[i])-1])
    
    # Normalize the result based on the number of runs
    normalized_result_trustees = [[] for i in range(len(relevant_dirnames))]
    normalized_result_people = [[] for i in range(len(relevant_dirnames))]
    total_runs_val = total_runs
    for i in range(len(result_trustees)):
        for result in result_trustees[i]:
            normalized_result_1 = [x / total_runs_val for x in result]
            normalized_result_trustees[i].append(normalized_result_1)
        for result in result_people[i]:
            normalized_result_2 = [x / total_runs_val for x in result]
            normalized_result_people[i].append(normalized_result_2)

    # print(normalized_result_people)

    # Plot the graph for number of trustees for all the parameter levels
    for i in range(len(relevant_dirnames)):
        x_vals = [i+1 for i in range(len(normalized_result_trustees[i][0]))]
        plt.plot(x_vals, normalized_result_trustees[i][0], label=str(legend[i]), linestyle=line_styles[i], linewidth=1.5)
        # Set labels and title
        plt.xlabel(x_labels[0], fontsize=21)
        plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='best')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)
    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-add-th-hinted-tr.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

    # Plot the graph for number of people for all the parameter levels
    for i in range(len(relevant_dirnames)):
        x_vals = [i+1 for i in range(len(normalized_result_people[i][0]))]
        plt.plot(x_vals, normalized_result_people[i][0], label=str(legend[i]), linestyle=line_styles[i], linewidth=1.5)

        # Set labels and title
        plt.xlabel(x_labels[1], fontsize=21)
        plt.ylabel(y_label, fontsize=21)
        plt.xticks(fontsize=18)
        plt.yticks(fontsize=18)
        plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='lower right')
        # plt.rc('text', usetex=True)
        plt.ylim(bottom=0)

    if h_line:
        plt.axhline(y=epsilon, color='red', linestyle='--', label='', linewidth=1)
        # plt.text(plt.xlim()[0], epsilon, f'{epsilon}', ha='right', va='bottom', fontsize=18, fontweight='bold')

    output_filename = output_path + '/plot-prob-cdf-' + varying + '-add-th-hinted-anon.pdf'
    plt.savefig(output_filename, format='pdf', dpi=1000, bbox_inches='tight')
    plt.cla()

def GenerateCDFData(data):
    sum_val = 0
    output = []
    for d in data:
        sum_val += d
        output.append(sum_val)
    # print(sum_val)
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
def extractStringData(filename, mode):
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

    if mode == 1:
        output["SubsecretsThreshold"] = data[5]
    elif mode == 2:
        output["Hints"] = data[5]
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