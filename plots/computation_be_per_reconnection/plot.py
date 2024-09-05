import matplotlib.pyplot as plt
import pandas as pd
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
    relevant_path = data['Folder']
    y_labels = data['YLabels']
    output_folder = data['OutputFolder']
    legend = data['Legend']
    time_modes = [0, 1, 2]
    time_units = ['s', 'mins', 'hrs']
    for key, value in (data['Data']).items():
        # if key != 'ATSS':
        # if not ((key != 'Anonymity') ^ (key != 'ATSS')):
        #     continue
        for time_mode in time_modes:
            plot(varying=key, 
                relevant_path=relevant_path,
                relevant_dirname=value['RelevantDir'], 
                relevant_column=value['RelevantColumn'],
                legend_mode=value['LegendMode'],
                legend=legend,
                y_label=y_labels[time_mode], 
                x_label=value['XLabel'], 
                output_folder=output_folder, 
                time_mode=time_mode, 
                time_unit=time_units[time_mode],
                strawman_num=value['StrawmanNum'],
                add_num=value['AddNum'])

def plot(varying, 
         relevant_path, 
         relevant_dirname, 
         relevant_column, 
         legend_mode, 
         legend, 
         y_label, 
         x_label, 
         output_folder, 
         time_mode, 
         time_unit,
         strawman_num,
         add_num):
    output_path = "./" + output_folder + "/"
    print(all_directories_exist(output_path))
    print(legend)

    if not all_directories_exist(output_path):
        os.makedirs(output_path)

    time_const = 1
    if time_mode == 0:
        time_const = 1e9
    elif time_mode == 1:
        time_const = 1e9 * 60
    elif time_mode == 2:
        time_const = 1e9 * 60 * 60

    base_dir = "./" + relevant_path + '/' + relevant_dirname
    
    if legend_mode == 1:
        file_1 = base_dir + '/add-results.csv'
        file_2 = base_dir + '/strawman-results.csv'
        if add_num != 0:
            add_df = pd.DataFrame()
            for i in range(add_num):
                f = "./" + relevant_path + '/' + relevant_dirname + '/add-results-' + str(i+1) + '.csv'
                df = pd.read_csv(f)
                add_df = pd.concat([add_df, df], ignore_index=True)
            df_sorted = add_df.sort_values(by=add_df.columns[1])

            # Optional: Reset the index if needed
            df_sorted.reset_index(drop=True, inplace=True)

            # Save the sorted dataframe to a new CSV file
            df_sorted.to_csv(file_1, index=False)
        if strawman_num != 0:
            add_df = pd.DataFrame()
            for i in range(strawman_num):
                f = "./" + relevant_path + '/' + relevant_dirname + '/strawman-results-' + str(i+1) + '.csv'
                df = pd.read_csv(f)
                add_df = pd.concat([add_df, df], ignore_index=True)
            df_sorted = add_df.sort_values(by=add_df.columns[1])

            # Optional: Reset the index if needed
            df_sorted.reset_index(drop=True, inplace=True)

            # Save the sorted dataframe to a new CSV file
            df_sorted.to_csv(file_2, index=False)

        dfs = []
        dfs.append(pd.read_csv(file_1))
        dfs.append(pd.read_csv(file_2))

        for df in dfs:
            df.iloc[:, 4] /= time_const
            grouped_df = df.groupby(df.iloc[:, relevant_column])
            mean_values = grouped_df.mean()
            std_values = grouped_df.std()

            # Plot the mean values with error bars representing standard deviation
            plt.plot(mean_values.index, mean_values.iloc[:, 4], linewidth=2)
            # plt.errorbar(mean_values.index, mean_values.iloc[:, 4], yerr=std_values.iloc[:, 4], fmt='-o')
            # plt.fill_between(mean_values.index, mean_values.iloc[:, 4] - std_values.iloc[:, 4], mean_values.iloc[:, 4] + std_values.iloc[:, 4], alpha=0.8)
            plt.legend(legend, fontsize='xx-large', title_fontsize='xx-large', loc='best')

    elif legend_mode == 2:
        file = "./" + relevant_path + '/' + relevant_dirname + '/add-results.csv'
        df = pd.read_csv(file)

        # filtered_df = df[df.columns[5]]
        filtered_df = df

        filtered_df.iloc[:, 4] /= time_const
        grouped_df = filtered_df.groupby(df.iloc[:, relevant_column])
        mean_values = grouped_df.mean()
        std_values = grouped_df.std()

        # Plot the mean values with error bars representing standard deviation
        # plt.bar(mean_values.index, log_mean_values)
        plt.plot(mean_values.index, mean_values.iloc[:, 4], linewidth=2, marker='o')
        plt.xticks(ticks=mean_values.index, labels=mean_values.index.astype(int))

    else:
        file = "./" + relevant_path + '/' + relevant_dirname + '/add-results.csv'
        df = pd.read_csv(file)

        # unique_ats = df[df.columns[5]].unique()
        # print(unique_ats)

        df.iloc[:, 4] /= time_const
        grouped_df = df.groupby(df.iloc[:, relevant_column])
        mean_values = grouped_df.mean()
        std_values = grouped_df.std()

        # Plot the mean values with error bars representing standard deviation
        # plt.bar(mean_values.index, mean_values.iloc[:, 4])
        plt.plot(mean_values.index, mean_values.iloc[:, 4], linewidth=2, marker='o')
        plt.xticks(ticks=mean_values.index, labels=mean_values.index.astype(int))

    plt.xlabel(x_label, fontsize=21)
    if varying == 'Anonymity':
        plt.ylabel(y_label, fontsize=21)
    plt.xticks(fontsize=18)
    plt.yticks(fontsize=18)

    filename = output_path + 'varying-' + varying + '-' + time_unit + '.pdf'
    plt.savefig(filename, bbox_inches='tight', dpi=1000)
    plt.cla()

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