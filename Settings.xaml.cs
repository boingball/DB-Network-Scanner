//Copyright(c) 2024, Darren Banfi
//All rights reserved.
//
//This source code is licensed under the BSD-style license found in the
//LICENSE file in the root directory of this source tree. 

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Scan_Network
{
    /// <summary>
    /// Interaction logic for Settings.xaml
    /// </summary>
    public partial class Settings : Window
    {
        public Settings()
        {
            InitializeComponent();
            SnipeITURL.Text = Properties.Settings.Default.SnipeITURL;
            SnipeITPAT.Text = Properties.Settings.Default.SnipeITPAT;
            if (Properties.Settings.Default.SnipeITSupport == true)
            {
                SnipeITCheck.IsChecked = true;
            } else { SnipeITCheck.IsChecked = false; }
            SnipeITCheck.Content = Properties.Settings.Default.SnipeITSupport;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            Properties.Settings.Default.SnipeITURL = SnipeITURL.Text;
            Properties.Settings.Default.SnipeITPAT = SnipeITPAT.Text;
            if (SnipeITCheck.IsChecked == true)
            {
                Properties.Settings.Default.SnipeITSupport = true;
            } else { Properties.Settings.Default.SnipeITSupport = false; }
            Properties.Settings.Default.Save();
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
