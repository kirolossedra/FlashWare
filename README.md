# FlashWare


# Step 1: Install Miniforge (minimal Conda with tkinter-ready Python)
brew install --cask miniforge

# Step 2: Restart terminal (only needed if conda command not found)
source ~/miniforge3/etc/profile.d/conda.sh

# Step 3: Create a fresh environment with Python and tkinter (tk)
conda create -n pyinstaller-env python=3.11 tk -y

# Step 4: Activate the environment
conda activate pyinstaller-env

# Step 5: Install pyinstaller
pip install pyinstaller

# Step 6: Confirm tkinter works (will pop up a test GUI)
python -c "import tkinter; tkinter._test()"

