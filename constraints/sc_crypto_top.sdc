# TEMPLATE timing constraints -- tune per PDK / target frequency.
# 13.56 MHz contactless smart cards are very slow; 50 MHz here leaves margin for
# the 258-bit compare/subtract chain in modmul_serial. Re-derive from STA.
create_clock -name clk -period 20.0 [get_ports clk]
set_clock_uncertainty 0.5 [get_clocks clk]
set_clock_transition  0.2 [get_clocks clk]

# CPU interface (assumed synchronous to clk)
set_input_delay  -clock clk 5.0 [remove_from_collection [all_inputs] [get_ports {clk rst_n_async thermal_noise_in}]]
set_output_delay -clock clk 5.0 [all_outputs]

# Asynchronous reset: async assert is unconstrained, release goes through reset_sync
set_false_path -from [get_ports rst_n_async]

# Thermal-noise comparator output is asynchronous by nature (entropy_sampler has 2-FF sync)
set_false_path -from [get_ports thermal_noise_in]

# Ring oscillators are intentional combinational loops: keep them out of STA
# and out of optimisation. Names depend on your tech_ro wrapper / macro instance.
# set_dont_touch [get_cells -hier *u_tech_ro*]
# set_disable_timing [get_cells -hier *u_tech_ro*]
# set_false_path -from [get_pins -hier *u_tech_ro*/osc]
