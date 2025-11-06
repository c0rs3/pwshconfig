-- Pull in the wezterm API
local wezterm = require 'wezterm'

-- This will hold the configuration.
local config = wezterm.config_builder()

-- This is where you actually apply your config choices.

-- For example, changing the initial geometry for new windows:
config.initial_cols = 120
config.initial_rows = 28

-- or, changing the font size and color scheme.
config.font_size = 10
config.color_scheme = 'AdventureTime'
config.default_prog = { 'pwsh.exe' }

-- Make background black and remove tab bar
config.enable_tab_bar = false
config.window_decorations = "RESIZE"  -- This removes the title bar but keeps resize handles
config.colors = {
    background = 'black',
}

-- If you want to remove ALL decorations (tabs, title bar, everything) use:
-- config.window_decorations = "NONE"

-- Finally, return the configuration to wezterm:
return config