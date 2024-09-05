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
    output_folder = "plots-final-1"
    output_path = "./" + output_folder + "/"
    print(all_directories_exist(output_path))

    if not all_directories_exist(output_path):
        os.makedirs(output_path)
    
    file_anon = "./results-anon.csv"
    file_th = "./results-th.csv"

    df = pd.read_csv(file_anon)
    # filtered_df = df[df.columns[5]]
    filtered_df = df[df.iloc[:, 1] % 10 == 0]
    filtered_df = filtered_df[filtered_df.iloc[:, 1] <= 150]
    filtered_df.iloc[:, 4] /= 102400
    filtered_df.iloc[:, 3] /= 102400
    filtered_df.iloc[:, 5] /= 102400
    grouped_df = filtered_df.groupby(df.iloc[:, 1])
    sum_values = grouped_df.sum()
    mean_values = grouped_df.sum()
    bar_width = 5
    
    # print(sum_values['Overall packet size'].iloc[0])

    # Plot the mean values with error bars representing standard deviation
    plt.plot(mean_values.index, mean_values.iloc[:, 3], linewidth=2, label='Total data')
    plt.fill_between(mean_values.index, mean_values.iloc[:, 5], color='skyblue', alpha=0.4, label='Relevant data')
    plt.fill_between(mean_values.index, mean_values.iloc[:, 5], mean_values.iloc[:, 3], color='lightcoral', alpha=0.4, label='Random data')
    # bars2_category1 = plt.bar(sum_values.index, sum_values.iloc[:, 5], width=bar_width, color='skyblue', edgecolor='black', alpha=0.7, label='Relevant Data')
    # bars2_category2 = plt.bar(sum_values.index, sum_values.iloc[:, 3], width=bar_width, bottom=sum_values.iloc[:, 5], color='lightcoral', edgecolor='black', alpha=0.7, label='Random Data')

    plt.xlabel("Privacy Pool Size", fontsize=21)
    plt.ylabel("Total size of data \n distributed (in kB)", fontsize=21)
    plt.xticks(fontsize=18)
    plt.ylim(0)
    # plt.xticks(ticks=sum_values.index, labels=sum_values.index.astype(int))
    plt.yticks(fontsize=18)
    plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='upper left', frameon=False)
    plt.tight_layout()

    filename = output_path + 'varying-anon' + '.pdf'
    plt.savefig(filename, bbox_inches='tight', dpi=1000)
    # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='best')
    plt.cla()

    df = pd.read_csv(file_th)
    filtered_df = df[df[df.columns[1]] == 150]
    # filtered_df = df[df.columns[5]]
    # filtered_df = df[df.iloc[:, 1] % 10 == 0]
    # filtered_df = filtered_df[filtered_df.iloc[:, 1] <= 150]
    filtered_df.iloc[:, 4] /= 102400
    filtered_df.iloc[:, 3] /= 102400
    filtered_df.iloc[:, 5] /= 102400
    grouped_df = filtered_df.groupby(df.iloc[:, 2])
    sum_values = grouped_df.sum()
    mean_values = grouped_df.sum()
    bar_width = 5
    print(df.dtypes)
    
    # print(sum_values['Overall packet size'].iloc[0])

    # Plot the mean values with error bars representing standard deviation
    plt.plot(mean_values.index, mean_values.iloc[:, 3], linewidth=2, label='Total data')
    plt.fill_between(mean_values.index, mean_values.iloc[:, 5], color='skyblue', alpha=0.4, label='Relevant data')
    plt.fill_between(mean_values.index, mean_values.iloc[:, 5], mean_values.iloc[:, 3], color='lightcoral', alpha=0.4, label='Random data')
    # bars2_category1 = plt.bar(sum_values.index, sum_values.iloc[:, 5], width=bar_width, color='skyblue', edgecolor='black', alpha=0.7, label='Relevant Data')
    # bars2_category2 = plt.bar(sum_values.index, sum_values.iloc[:, 3], width=bar_width, bottom=sum_values.iloc[:, 5], color='lightcoral', edgecolor='black', alpha=0.7, label='Random Data')

    plt.xlabel("Privacy Pool Size", fontsize=21)
    plt.ylabel("Total size of data \n distributed (in kB)", fontsize=21)
    plt.xticks(fontsize=18)
    # plt.xticks(ticks=sum_values.index, labels=sum_values.index.astype(int))
    plt.yticks(fontsize=18)
    plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='upper left', frameon=False)

    filename = output_path + 'varying-th' + '.pdf'
    plt.savefig(filename, bbox_inches='tight', pad_inches=0, dpi=1000)
    # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='best')
    plt.cla()

    # df = pd.read_csv(file_shares_per_person)
    # # filtered_df = df[df.columns[5]]
    # filtered_df = df
    # filtered_df.iloc[:, 4] /= 1024
    # filtered_df.iloc[:, 3] /= 1024
    # filtered_df.iloc[:, 5] /= 1024
    # grouped_df = filtered_df.groupby(df.iloc[:, 8])
    # sum_values = grouped_df.sum()
    # mean_values = grouped_df.mean()
    # bar_width = 0.3

    # # plt.plot(mean_values.index, mean_values.iloc[:, 3], linewidth=2, label='Total data')
    # # plt.fill_between(mean_values.index, mean_values.iloc[:, 5], color='skyblue', alpha=0.4, label='Relevant data')
    # # plt.fill_between(mean_values.index, mean_values.iloc[:, 5], mean_values.iloc[:, 3], color='lightcoral', alpha=0.4, label='Random data')
    # bars2_category1 = plt.bar(sum_values.index, sum_values.iloc[:, 5], width=bar_width, color='skyblue', edgecolor='black', alpha=0.7, label='Relevant Data')
    # bars2_category2 = plt.bar(sum_values.index, sum_values.iloc[:, 3], width=bar_width, bottom=sum_values.iloc[:, 5], color='lightcoral', edgecolor='black', alpha=0.7, label='Random Data')

    # plt.xlabel("Privacy Pool Size", fontsize=21)
    # plt.ylabel("Total size of data \n distributed (in kB)", fontsize=21)
    # # plt.xticks(fontsize=18)
    # plt.xticks(ticks=sum_values.index, labels=sum_values.index.astype(int), fontsize=18)
    # plt.yticks(fontsize=18)
    # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='upper left')

    # filename = output_path + 'varying-per-packet-shares-per-person' + '.pdf'
    # plt.savefig(filename, bbox_inches='tight', dpi=1000)
    # # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='best')
    # plt.cla()

    # Plot the mean values with error bars representing standard deviation
    # plt.bar(mean_values.index, log_mean_values)
    # plt.plot(sum_values.index, sum_values.iloc[:, 3], linewidth=2, label='Total data')
    # plt.xticks(ticks=sum_values.index, labels=sum_values.index.astype(int))
    # plt.fill_between(sum_values.index, sum_values.iloc[:, 5], color='skyblue', alpha=0.4, label='Relevant data')
    # plt.fill_between(sum_values.index, sum_values.iloc[:, 5], sum_values.iloc[:, 3], color='lightcoral', alpha=0.4, label='Random data')

    # plt.xlabel("No. of shares per packet", fontsize=21)
    # plt.ylabel("Total size of data \n distributed (in kB)", fontsize=21)
    # plt.xticks(fontsize=18)
    # plt.yticks(fontsize=18)
    # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='upper left')

    # filename = output_path + 'varying-shares-per-person' + '.pdf'
    # plt.savefig(filename, bbox_inches='tight', dpi=1000)
    # # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='best')
    # plt.cla()

    # plt.bar(mean_values.index, mean_values.iloc[:, 3], width=0.4)
    # plt.xticks(ticks=sum_values.index, labels=sum_values.index.astype(int))

    # plt.xlabel("No. of shares per packet", fontsize=21)
    # plt.ylabel("Size of packet (in kB)", fontsize=21)
    # plt.xticks(fontsize=18)
    # plt.yticks(fontsize=18)
    # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='upper left')

    # fig, ax1 = plt.subplots(figsize=(5, 4))

    # # Create the first bar graph for y1
    # bar_width = 0.3

    # # Create stacked bar chart for y2
    # bars2_category1 = ax1.bar(sum_values.index, sum_values.iloc[:, 5], width=bar_width, color='skyblue', edgecolor='black', alpha=0.7, label='Relevant Data')
    # bars2_category2 = ax1.bar(sum_values.index, sum_values.iloc[:, 3], width=bar_width, bottom=sum_values.iloc[:, 5], color='lightcoral', edgecolor='black', alpha=0.7, label='Random Data')
    # ax1.set_ylabel('Total size of data \n distributed (in kB)', fontsize=21)
    # ax1.tick_params(axis='y')
    # ax1.set_xlabel('No. of shares per packet', fontsize=21)
    # plt.xticks(fontsize=18)
    # plt.yticks(fontsize=18)

    # # Create the second Y axis
    # ax2 = ax1.twinx()

    # default_blue = (0.12156863, 0.46666667, 0.70588235)
    # ax2.plot(mean_values.index, mean_values.iloc[:, 3], label='Packet size', marker='o', linewidth=2, color=default_blue)
    # # ax2.set_ylabel('Packet size (in kB)', fontsize=21, color=default_blue)
    # ax2.set_ylabel('Packet size (in kB)', fontsize=21)
    # ax2.grid(False)  # Disable grid for secondary y-axis to avoid clutter
    # plt.xticks(ticks=sum_values.index, labels=sum_values.index.astype(int))
    # plt.xticks(fontsize=18)
    # plt.yticks(fontsize=18)
    # # Add legends for both the line and the bar chart
    # fig.legend(loc='upper left', bbox_to_anchor=(0.1,0.9), fontsize='xx-large', title_fontsize='xx-large')

    # filename = output_path + 'varying-per-packet-shares-per-person' + '.pdf'
    # plt.savefig(filename, bbox_inches='tight', dpi=1000)
    # # plt.legend(fontsize='xx-large', title_fontsize='xx-large', loc='best')
    # plt.cla()

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