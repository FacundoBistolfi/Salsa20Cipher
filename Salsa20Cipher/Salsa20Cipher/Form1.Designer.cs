﻿namespace Salsa20Cipher
{
    partial class Form1
    {
        /// <summary>
        /// Variable del diseñador requerida.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Limpiar los recursos que se estén utilizando.
        /// </summary>
        /// <param name="disposing">true si los recursos administrados se deben eliminar; false en caso contrario.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Código generado por el Diseñador de Windows Forms

        /// <summary>
        /// Método necesario para admitir el Diseñador. No se puede modificar
        /// el contenido del método con el editor de código.
        /// </summary>
        private void InitializeComponent()
        {
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.label6 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.tbOut = new System.Windows.Forms.TextBox();
            this.tbIn = new System.Windows.Forms.TextBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.btnOut = new System.Windows.Forms.Button();
            this.btnIn = new System.Windows.Forms.Button();
            this.tbOutPath = new System.Windows.Forms.TextBox();
            this.tbInPath = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
            this.label8 = new System.Windows.Forms.Label();
            this.panel1 = new System.Windows.Forms.Panel();
            this.label10 = new System.Windows.Forms.Label();
            this.pbar = new System.Windows.Forms.ProgressBar();
            this.btnGo = new System.Windows.Forms.Button();
            this.tbTime = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.rb10 = new System.Windows.Forms.RadioButton();
            this.rb16 = new System.Windows.Forms.RadioButton();
            this.rb32 = new System.Windows.Forms.RadioButton();
            this.label3 = new System.Windows.Forms.Label();
            this.rbAuto = new System.Windows.Forms.RadioButton();
            this.label1 = new System.Windows.Forms.Label();
            this.tbNonce = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.tbKey = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.panel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Location = new System.Drawing.Point(1, 6);
            this.tabControl1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(643, 510);
            this.tabControl1.SizeMode = System.Windows.Forms.TabSizeMode.FillToRight;
            this.tabControl1.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.label6);
            this.tabPage1.Controls.Add(this.label5);
            this.tabPage1.Controls.Add(this.tbOut);
            this.tabPage1.Controls.Add(this.tbIn);
            this.tabPage1.Location = new System.Drawing.Point(4, 25);
            this.tabPage1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage1.Size = new System.Drawing.Size(635, 481);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Texto";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(9, 256);
            this.label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(47, 17);
            this.label6.TabIndex = 5;
            this.label6.Text = "Salida";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(9, 10);
            this.label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(58, 17);
            this.label5.TabIndex = 4;
            this.label5.Text = "Entrada";
            // 
            // tbOut
            // 
            this.tbOut.Location = new System.Drawing.Point(4, 276);
            this.tbOut.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbOut.Multiline = true;
            this.tbOut.Name = "tbOut";
            this.tbOut.Size = new System.Drawing.Size(612, 194);
            this.tbOut.TabIndex = 3;
            // 
            // tbIn
            // 
            this.tbIn.Location = new System.Drawing.Point(4, 30);
            this.tbIn.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbIn.Multiline = true;
            this.tbIn.Name = "tbIn";
            this.tbIn.Size = new System.Drawing.Size(612, 203);
            this.tbIn.TabIndex = 0;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.btnOut);
            this.tabPage2.Controls.Add(this.btnIn);
            this.tabPage2.Controls.Add(this.tbOutPath);
            this.tabPage2.Controls.Add(this.tbInPath);
            this.tabPage2.Controls.Add(this.label9);
            this.tabPage2.Controls.Add(this.label8);
            this.tabPage2.Location = new System.Drawing.Point(4, 25);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage2.Size = new System.Drawing.Size(635, 481);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Archivo";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // btnOut
            // 
            this.btnOut.Location = new System.Drawing.Point(416, 96);
            this.btnOut.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnOut.Name = "btnOut";
            this.btnOut.Size = new System.Drawing.Size(100, 28);
            this.btnOut.TabIndex = 5;
            this.btnOut.Text = "Seleccionar";
            this.btnOut.UseVisualStyleBackColor = true;
            this.btnOut.Click += new System.EventHandler(this.btnOut_Click);
            // 
            // btnIn
            // 
            this.btnIn.Location = new System.Drawing.Point(416, 30);
            this.btnIn.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnIn.Name = "btnIn";
            this.btnIn.Size = new System.Drawing.Size(100, 28);
            this.btnIn.TabIndex = 4;
            this.btnIn.Text = "Seleccionar";
            this.btnIn.UseVisualStyleBackColor = true;
            this.btnIn.Click += new System.EventHandler(this.btnIn_Click);
            // 
            // tbOutPath
            // 
            this.tbOutPath.Location = new System.Drawing.Point(9, 92);
            this.tbOutPath.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbOutPath.Name = "tbOutPath";
            this.tbOutPath.ReadOnly = true;
            this.tbOutPath.Size = new System.Drawing.Size(399, 22);
            this.tbOutPath.TabIndex = 3;
            // 
            // tbInPath
            // 
            this.tbInPath.Location = new System.Drawing.Point(8, 30);
            this.tbInPath.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbInPath.Name = "tbInPath";
            this.tbInPath.ReadOnly = true;
            this.tbInPath.Size = new System.Drawing.Size(399, 22);
            this.tbInPath.TabIndex = 2;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(8, 63);
            this.label9.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(47, 17);
            this.label9.TabIndex = 1;
            this.label9.Text = "Salida";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(4, 6);
            this.label8.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(58, 17);
            this.label8.TabIndex = 0;
            this.label8.Text = "Entrada";
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.label10);
            this.panel1.Controls.Add(this.pbar);
            this.panel1.Controls.Add(this.btnGo);
            this.panel1.Controls.Add(this.tbTime);
            this.panel1.Controls.Add(this.label7);
            this.panel1.Controls.Add(this.rb10);
            this.panel1.Controls.Add(this.rb16);
            this.panel1.Controls.Add(this.rb32);
            this.panel1.Controls.Add(this.label3);
            this.panel1.Controls.Add(this.rbAuto);
            this.panel1.Controls.Add(this.label1);
            this.panel1.Controls.Add(this.tbNonce);
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.tbKey);
            this.panel1.Controls.Add(this.label4);
            this.panel1.Location = new System.Drawing.Point(652, 15);
            this.panel1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(516, 455);
            this.panel1.TabIndex = 20;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(28, 411);
            this.label10.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(54, 17);
            this.label10.TabIndex = 28;
            this.label10.Text = "label10";
            this.label10.Visible = false;
            // 
            // pbar
            // 
            this.pbar.Location = new System.Drawing.Point(25, 379);
            this.pbar.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.pbar.Name = "pbar";
            this.pbar.Size = new System.Drawing.Size(461, 28);
            this.pbar.Step = 1;
            this.pbar.TabIndex = 27;
            this.pbar.Visible = false;
            this.pbar.Click += new System.EventHandler(this.progressBar1_Click);
            // 
            // btnGo
            // 
            this.btnGo.Location = new System.Drawing.Point(24, 294);
            this.btnGo.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnGo.Name = "btnGo";
            this.btnGo.Size = new System.Drawing.Size(463, 78);
            this.btnGo.TabIndex = 26;
            this.btnGo.Text = "ENCRIPTAR / DESENCRIPTAR";
            this.btnGo.UseVisualStyleBackColor = true;
            this.btnGo.Click += new System.EventHandler(this.btnGo_Click);
            // 
            // tbTime
            // 
            this.tbTime.Location = new System.Drawing.Point(244, 249);
            this.tbTime.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbTime.Name = "tbTime";
            this.tbTime.ReadOnly = true;
            this.tbTime.Size = new System.Drawing.Size(128, 22);
            this.tbTime.TabIndex = 25;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(21, 252);
            this.label7.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(217, 17);
            this.label7.TabIndex = 6;
            this.label7.Text = "Tiempo ultima encriptación (ms): ";
            // 
            // rb10
            // 
            this.rb10.AutoSize = true;
            this.rb10.Location = new System.Drawing.Point(272, 139);
            this.rb10.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rb10.Name = "rb10";
            this.rb10.Size = new System.Drawing.Size(76, 21);
            this.rb10.TabIndex = 24;
            this.rb10.Text = "10 byte";
            this.rb10.UseVisualStyleBackColor = true;
            this.rb10.CheckedChanged += new System.EventHandler(this.rb10_CheckedChanged);
            // 
            // rb16
            // 
            this.rb16.AutoSize = true;
            this.rb16.Location = new System.Drawing.Point(184, 139);
            this.rb16.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rb16.Name = "rb16";
            this.rb16.Size = new System.Drawing.Size(76, 21);
            this.rb16.TabIndex = 23;
            this.rb16.Text = "16 byte";
            this.rb16.UseVisualStyleBackColor = true;
            this.rb16.CheckedChanged += new System.EventHandler(this.rb16_CheckedChanged);
            // 
            // rb32
            // 
            this.rb32.AutoSize = true;
            this.rb32.Location = new System.Drawing.Point(96, 139);
            this.rb32.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rb32.Name = "rb32";
            this.rb32.Size = new System.Drawing.Size(76, 21);
            this.rb32.TabIndex = 22;
            this.rb32.Text = "32 byte";
            this.rb32.UseVisualStyleBackColor = true;
            this.rb32.CheckedChanged += new System.EventHandler(this.rb32_CheckedChanged);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(21, 114);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(61, 17);
            this.label3.TabIndex = 21;
            this.label3.Text = "Key size";
            this.label3.Click += new System.EventHandler(this.label3_Click);
            // 
            // rbAuto
            // 
            this.rbAuto.AutoSize = true;
            this.rbAuto.Checked = true;
            this.rbAuto.Location = new System.Drawing.Point(25, 139);
            this.rbAuto.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rbAuto.Name = "rbAuto";
            this.rbAuto.Size = new System.Drawing.Size(58, 21);
            this.rbAuto.TabIndex = 20;
            this.rbAuto.TabStop = true;
            this.rbAuto.Text = "Auto";
            this.rbAuto.UseVisualStyleBackColor = true;
            this.rbAuto.CheckedChanged += new System.EventHandler(this.rbAuto_CheckedChanged);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(21, 183);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(49, 17);
            this.label1.TabIndex = 18;
            this.label1.Text = "Nonce";
            // 
            // tbNonce
            // 
            this.tbNonce.Location = new System.Drawing.Point(24, 203);
            this.tbNonce.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbNonce.MaxLength = 8;
            this.tbNonce.Name = "tbNonce";
            this.tbNonce.Size = new System.Drawing.Size(407, 22);
            this.tbNonce.TabIndex = 17;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(20, 52);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(32, 17);
            this.label2.TabIndex = 16;
            this.label2.Text = "Key";
            // 
            // tbKey
            // 
            this.tbKey.Location = new System.Drawing.Point(24, 73);
            this.tbKey.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tbKey.MaxLength = 32;
            this.tbKey.Name = "tbKey";
            this.tbKey.Size = new System.Drawing.Size(407, 22);
            this.tbKey.TabIndex = 15;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(20, 18);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(254, 25);
            this.label4.TabIndex = 0;
            this.label4.Text = "Configuración SALSA 20";
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1184, 530);
            this.Controls.Add(this.panel1);
            this.Controls.Add(this.tabControl1);
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "Form1";
            this.Text = "SALSA 20 Cipher";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TextBox tbOut;
        private System.Windows.Forms.TextBox tbIn;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.RadioButton rb10;
        private System.Windows.Forms.RadioButton rb16;
        private System.Windows.Forms.RadioButton rb32;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.RadioButton rbAuto;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox tbNonce;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox tbKey;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox tbTime;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Button btnGo;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Button btnIn;
        private System.Windows.Forms.TextBox tbOutPath;
        private System.Windows.Forms.TextBox tbInPath;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Button btnOut;
        private System.Windows.Forms.ProgressBar pbar;
        private System.Windows.Forms.Label label10;
    }
}

