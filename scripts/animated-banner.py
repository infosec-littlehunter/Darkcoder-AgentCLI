import sys
import time
import random

# Fire-themed gradient colors
DARK_RED = "\033[38;2;139;0;0m"
BRIGHT_RED = "\033[38;2;255;0;0m"
ORANGE = "\033[38;2;255;69;0m"
GOLD = "\033[38;2;255;215;0m"
YELLOW = "\033[38;2;255;255;0m"
MATRIX_GREEN = "\033[38;2;0;255;65m"
CYAN = "\033[38;2;0;255;255m"
WHITE = "\033[38;2;255;255;255m"
RESET = "\033[0m"

# Multiple ASCII art banners with different text
banners = [
    # Banner 1: CYBERSEC FLOW HACKER
    """ 
██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
    ███████╗██╗      ██████╗ ██╗    ██╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗
    ██╔════╝██║     ██╔═══██╗██║    ██║    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
    █████╗  ██║     ██║   ██║██║ █╗ ██║    ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
    ██╔══╝  ██║     ██║   ██║██║███╗██║    ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
    ██║     ███████╗╚██████╔╝╚███╔███╔╝    ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
    ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝""",
]

# Banner 7: Animated Rotating Planet (Special)
planet_banner = "PLANET"

# Banner 8: Animated Van Drive-Through (Special)
van_banner = "VAN"

# Banner 9: Animated Rocket Crash (Special)
rocket_banner = "ROCKET"

# Randomly select a banner (equal chance for static, planet, van, or rocket animation)
selected_banner_type = random.choice(["static", "planet", "van", "rocket"])

if selected_banner_type == "planet":
    text = planet_banner
else:
    text = random.choice(banners)

lines = text.split('\n')


# Fire gradient for each line (top to bottom: red → orange → gold → green)
# Extend or repeat colors to match the number of lines
base_gradient = [DARK_RED, DARK_RED, BRIGHT_RED, ORANGE, ORANGE, GOLD, GOLD, YELLOW, YELLOW, MATRIX_GREEN, MATRIX_GREEN, MATRIX_GREEN]
gradient = []
for i in range(len(lines)):
    gradient.append(base_gradient[i % len(base_gradient)])

def animate_subtitle():
    pass  # Subtitle animation removed for redesign

def animate_planet_banner():
    """Animated rotating planet with cool title - compact version"""
    # Planet rotation frames - Earth-like with blue oceans (░) and green/brown continents (▓█)
    planet_frames = [
        # Frame 1 - Americas visible
        [
            "       ██████████       ",
            "     ██░░░░░░░░░░██     ",
            "    ██░░░░▓▓██░░░░██    ",
            "   ██░░░░▓▓▓██▓░░░░██   ",
            "  ██░░░░░▓▓███▓░░░░░██  ",
            "  ██░░░░░░▓███░░░░░░██  ",
            "   ██░░░░░░▓█░░░░░░██   ",
            "    ██░░░░░░░░░░░░██    ",
            "     ██░░░░░░░░░░██     ",
            "       ██████████       "
        ],
        # Frame 2 - Americas rotating right
        [
            "       ██████████       ",
            "     ██░░░░░░░░░░██     ",
            "    ██░░░▓▓██▓░░░░██    ",
            "   ██░░░▓▓▓██▓▓░░░░██   ",
            "  ██░░░░▓▓███▓▓░░░░░██  ",
            "  ██░░░░░▓███▓░░░░░░██  ",
            "   ██░░░░░▓█▓░░░░░░██   ",
            "    ██░░░░░░░░░░░░██    ",
            "     ██░░░░░░░░░░██     ",
            "       ██████████       "
        ],
        # Frame 3 - Atlantic Ocean
        [
            "       ██████████       ",
            "     ██░░░░░░░░░░██     ",
            "    ██░░░░▓█▓▓░░░░██    ",
            "   ██░░░░▓███▓▓░░░░██   ",
            "  ██░░░░▓████▓▓▓░░░░██  ",
            "  ██░░░░▓████▓▓░░░░░██  ",
            "   ██░░░░▓██▓░░░░░░██   ",
            "    ██░░░░░░░░░░░░██    ",
            "     ██░░░░░░░░░░██     ",
            "       ██████████       "
        ],
        # Frame 4 - Africa & Europe visible
        [
            "       ██████████       ",
            "     ██░░░░░░░░░░██     ",
            "    ██░░░░░▓█▓▓▓▓██     ",
            "   ██░░░░░▓███▓▓▓▓██    ",
            "  ██░░░░░▓████▓▓▓▓▓██   ",
            "  ██░░░░░▓████▓▓▓▓░██   ",
            "   ██░░░░▓███▓▓░░░██    ",
            "    ██░░░░▓█░░░░░██     ",
            "     ██░░░░░░░░░░██     ",
            "       ██████████       "
        ],
        # Frame 5 - Asia appearing
        [
            "       ██████████       ",
            "     ██░░░░░░░░░░██     ",
            "    ██░░░░░░▓▓▓▓███     ",
            "   ██░░░░░░▓██▓▓▓███    ",
            "  ██░░░░░░▓███▓▓▓███    ",
            "  ██░░░░░░▓████▓▓▓██    ",
            "   ██░░░░░▓███▓▓░██     ",
            "    ██░░░░░▓█░░░██      ",
            "     ██░░░░░░░░░░██     ",
            "       ██████████       "
        ],
        # Frame 6 - Pacific Ocean
        [
            "       ██████████       ",
            "     ██░░░░░░░░░░██     ",
            "    ██░░░░░░░▓▓███      ",
            "   ██░░░░░░░▓█▓▓███     ",
            "  ██░░░░░░░░██▓▓███     ",
            "  ██░░░░░░░░██▓▓██      ",
            "   ██░░░░░░░▓█▓██       ",
            "    ██░░░░░░░░██        ",
            "     ██░░░░░░░░░░██     ",
            "       ██████████       "
        ]
    ]
    
    # Full title lines (will be revealed letter by letter)
    full_title_lines = [
        " ██████╗██╗   ██╗██████╗ ███████╗██████╗ ",
        "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗",
        "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝",
        "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗",
        "╚██████╗   ██║   ██████╔╝███████╗██║  ██║",
        " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝",
        "                                          ",
        " ██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ",
        " ██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗",
        " ██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║",
        " ╚███╔███╔╝╚██████╔╝██╔══██╗███████╗██████╔╝",
        "  ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ "
    ]
    
    # Calculate max width for title
    max_title_width = max(len(line) for line in full_title_lines)
    
    # Animate the planet rotating with letter-by-letter title reveal (2 cycles)
    total_frames = len(planet_frames) * 2
    chars_per_frame = max_title_width // total_frames + 1
    
    for cycle in range(2):
        for frame_idx, frame in enumerate(planet_frames):
            # Clear and position cursor at top
            sys.stdout.write("\033[H")
            
            # Calculate how many characters to reveal
            current_frame = cycle * len(planet_frames) + frame_idx
            reveal_chars = current_frame * chars_per_frame
            
            # Calculate colors for this frame
            frame_colors = [CYAN, CYAN, MATRIX_GREEN, MATRIX_GREEN, GOLD, ORANGE]
            planet_color = frame_colors[frame_idx % len(frame_colors)]
            
            # Build title lines with partial reveal
            title_lines = []
            for line in full_title_lines:
                if reveal_chars >= len(line):
                    title_lines.append(line)  # Full line revealed
                else:
                    title_lines.append(line[:reveal_chars] + " " * (len(line) - reveal_chars))
            
            # Calculate padding to center everything
            output_lines = []
            max_lines = max(len(frame), len(title_lines))
            
            for i in range(max_lines):
                line = ""
                # Add planet
                if i < len(frame):
                    line += f"{planet_color}{frame[i]}{RESET}"
                else:
                    line += " " * 25
                
                line += "  "  # Small gap
                
                # Add title with reveal animation
                if i < len(title_lines):
                    title_color = gradient[i % len(gradient)] if i < len(gradient) else GOLD
                    line += f"{title_color}{title_lines[i]}{RESET}"
                
                output_lines.append(line)
            
            # Print all lines
            for line in output_lines:
                sys.stdout.write(line + "\n")
            
            sys.stdout.flush()
            time.sleep(0.12)
    
    # Final static frame with full title
    sys.stdout.write("\033[H")
    for i in range(max(len(planet_frames[0]), len(full_title_lines))):
        line = ""
        if i < len(planet_frames[0]):
            line += f"{CYAN}{planet_frames[0][i]}{RESET}"
        else:
            line += " " * 25
        
        line += "  "
        
        if i < len(full_title_lines):
            title_color = gradient[i % len(gradient)] if i < len(gradient) else GOLD
            line += f"{title_color}{full_title_lines[i]}{RESET}"
        
        sys.stdout.write(line + "\n")
    
    sys.stdout.flush()
    print("\n")

def animate_van_banner():
    """Van drives across screen, spits out title letter-by-letter, then disappears"""
    
    # Compact van design with more detail
    van_frames = [
        # Frame 1
        [
            "  ___________",
            " |≡ VAN ≡|▓▓>",
            " |_______|▓▓|",
            "  ◉◉◉   ◉◉◉"
        ],
        # Frame 2
        [
            "  ___________",
            " |≡ VAN ≡|▓▓>",
            " |_______|▓▓|",
            "  ⊚⊚⊚   ⊚⊚⊚"
        ],
        # Frame 3
        [
            "  ___________",
            " |≡ VAN ≡|▓▓>",
            " |_______|▓▓|",
            "  ◉◉◉   ◉◉◉"
        ],
        # Frame 4
        [
            "  ___________",
            " |≡ VAN ≡|▓▓>",
            " |_______|▓▓|",
            "  ⊚⊚⊚   ⊚⊚⊚"
        ]
    ]
    
    # Motion blur trail particles
    motion_particles = ["▓", "▒", "░", "·"]
    
    # ASCII art title that will be revealed
    ascii_title = [
        " ██████╗ ██████╗ ██████╗ ███████╗██████╗     ██╗  ██╗██╗  ██╗",
        "██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗    ██║ ██╔╝██║  ██║",
        "██║     ██║   ██║██║  ██║█████╗  ██████╔╝    █████╔╝ ███████║",
        "██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗    ██╔═██╗ ██╔══██║",
        "╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║    ██║  ██╗██║  ██║",
        " ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝",
        "                                                              ",
        "        ███████╗ ██████╗ ██████╗     ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ",
        "        ██╔════╝██╔═══██╗██╔══██╗    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗",
        "        █████╗  ██║   ██║██████╔╝    ███████║███████║██║     █████╔╝ █████╗  ██████╔╝",
        "        ██╔══╝  ██║   ██║██╔══██╗    ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗",
        "        ██║     ╚██████╔╝██║  ██║    ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║",
        "        ╚═╝      ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
    ]
    
    # Calculate max width for title
    max_title_width = max(len(line) for line in ascii_title)
    
    # Screen width and starting position
    screen_width = 80
    van_width = 13  # Compact van width
    
    # Phase 1: Van drives across and spits out letters
    total_chars = sum(len(line) for line in ascii_title)
    chars_revealed = 0
    
    for position in range(-van_width, screen_width + 20):
        sys.stdout.write("\033[H")  # Move to top
    # Screen width and starting position
    screen_width = 80
    van_width = 30
    
    # Phase 1: Van drives across and spits out letters
    total_chars = sum(len(line) for line in ascii_title)
    chars_revealed = 0
    
    for position in range(-van_width, screen_width + 20):
        sys.stdout.write("\033[H")  # Move to top
        
        # Calculate which frame to show (faster rotation)
        frame_idx = (position // 2) % len(van_frames)
        current_frame = van_frames[frame_idx]
        
        # Calculate how many characters of title to reveal (spit out as van moves)
        chars_per_frame = 4  # Faster reveal
        if position > 5:
            chars_revealed = min(total_chars, (position - 5) * chars_per_frame)
        
        # Dynamic color cycling for van with glow effect
        van_colors = [CYAN, MATRIX_GREEN, GOLD, ORANGE, BRIGHT_RED]
        van_color = van_colors[(position // 4) % len(van_colors)]
        
        # Accent color for speed lines
        accent_color = ORANGE if position % 4 < 2 else BRIGHT_RED
        
        # Build output
        output = []
        
        # Calculate vertical centering for title
        start_row = 3
        
        # Print van lines with motion blur and exhaust (only if van is still on screen)
        show_van = position < screen_width - 15  # Van disappears earlier
        
        if show_van:
            for i, line in enumerate(current_frame):
                spaces_before = max(0, position)
                
                # Create motion blur trail behind van (compact)
                motion_trail = ""
                if position > 0 and i in [2, 3]:  # Add trail to bottom lines
                    trail_length = min(6, position)
                    for t in range(trail_length):
                        particle = motion_particles[t % len(motion_particles)]
                        particle_color = van_colors[(position - t) % len(van_colors)]
                        motion_trail = f"{particle_color}{particle}{RESET}" + motion_trail
                    motion_trail = " " * max(0, spaces_before - trail_length) + motion_trail
                else:
                    motion_trail = " " * spaces_before
                
                # Build the line with van
                if i in [2, 3]:
                    display_line = motion_trail
                else:
                    display_line = " " * spaces_before
                
                if spaces_before < screen_width:
                    display_line += f"{van_color}{line}{RESET}"
                    
                    # Add speed lines and exhaust after van
                    if i == 1 and position > 5:
                        speed_effect = "━━>" if position % 2 == 0 else "═══>"
                        display_line += f" {accent_color}{speed_effect}{RESET}"
                    elif i == 2 and position % 3 == 0:
                        # Add exhaust puff effect
                        display_line += f" {WHITE}◌{RESET}"
                
                output.append(display_line)
        else:
            # Van has disappeared, add empty lines
            for _ in range(len(van_frames[0])):
                output.append("")
        
        # Add minimal spacing before title
        output.append("")
        
        # Build the title with progressive reveal
        char_count = 0
        for line_idx, line in enumerate(ascii_title):
            revealed_line = ""
            for char_idx, char in enumerate(line):
                if char_count < chars_revealed:
                    # Character is revealed with color and glow effect
                    color = gradient[line_idx % len(gradient)]
                    # Add glow to certain characters
                    if char != " " and char_count % 10 == 0 and position % 2 == 0:
                        revealed_line += f"{color}░{char}░{RESET}"
                        char_count += 1
                        continue
                    revealed_line += f"{color}{char}{RESET}"
                else:
                    # Character not yet revealed - show faint ghost
                    if char != " " and position > 10:
                        revealed_line += f"{WHITE}·{RESET}"
                    else:
                        revealed_line += " "
                char_count += 1
            
            # Center the line
            centered_line = revealed_line.center(screen_width)
            output.append(centered_line)
        
        # Add dynamic particle effects based on reveal progress
        if chars_revealed > 50:
            particle_intensity = min(5, chars_revealed // 100)
            particles = ""
            for p in range(particle_intensity):
                particle_colors = [GOLD, CYAN, ORANGE, BRIGHT_RED, MATRIX_GREEN]
                p_color = particle_colors[p % len(particle_colors)]
                particles += f"{p_color}✦{RESET} "
            output.append(particles.center(screen_width))
        
        # Print all output lines
        for line in output:
            sys.stdout.write(line + "\n")
        
        sys.stdout.flush()
        time.sleep(0.05)  # Smooth, fast animation
        
        # Stop when van has disappeared and enough text revealed
        if not show_van and chars_revealed >= total_chars - 100:
            # Continue showing text reveal for a moment after van disappears
            continue
        
        # Exit loop when animation is complete
        if position >= screen_width - 15 and chars_revealed >= total_chars:
            break
    
    # Phase 2: Final display with enhanced pulsing effect (van is gone, only title remains)
    for pulse in range(6):
        sys.stdout.write("\033[H")
        
        # Empty space where van was (compact)
        for _ in range(len(van_frames[0]) + 1):
            sys.stdout.write("\n")
        
        # Pulsing title with wave effect
        pulse_colors = [CYAN, GOLD, ORANGE, BRIGHT_RED, MATRIX_GREEN, CYAN]
        pulse_color = pulse_colors[pulse % len(pulse_colors)]
        
        for line_idx, line in enumerate(ascii_title):
            # Create wave effect across lines
            wave_offset = (pulse + line_idx) % 2
            if wave_offset == 0:
                color = pulse_color
            else:
                color = gradient[line_idx % len(gradient)]
            
            centered_line = line.center(screen_width)
            sys.stdout.write(f"{color}{centered_line}{RESET}\n")
        
        # Animated particles with rotation
        particle_sets = [
            f"{GOLD}✦{RESET} {CYAN}✧{RESET} {ORANGE}✦{RESET}",
            f"{CYAN}✧{RESET} {ORANGE}✦{RESET} {GOLD}✦{RESET}",
            f"{ORANGE}✦{RESET} {GOLD}✦{RESET} {CYAN}✧{RESET}"
        ]
        particle_line = particle_sets[pulse % len(particle_sets)]
        sys.stdout.write(particle_line.center(screen_width) + "\n")
        
        # Add underlighting effect
        if pulse % 2 == 0:
            underlight = f"{pulse_color}{'░' * 20}{RESET}"
            sys.stdout.write(underlight.center(screen_width) + "\n")
        
        sys.stdout.flush()
        time.sleep(0.18)
    
    print("\n")

def animate_rocket_banner():
    """Rocket crashes down with fire explosion and reveals title"""
    
    # Rocket frames (descending) - Enhanced design
    rocket_frames = [
        # Frame 1
        [
            "        ▲        ",
            "       ╱█╲       ",
            "      ╱███╲      ",
            "     │█████│     ",
            "     │█▓▓▓█│     ",
            "     │█▒▒▒█│     ",
            "     │█░░░█│     ",
            "    ╱███████╲    ",
            "   ╱█████████╲   ",
            "  ││ ▓▓▓▓▓ ││  ",
            "  ││ ▒▒▒▒▒ ││  ",
            "   ╲╲     ╱╱   ",
            "    ╲╲═══╱╱    ",
            "     ╲═══╱     ",
            "    ▓▓█▓▓█▓▓    ",
            "    ▒▒▓▒▒▓▒▒    ",
            "    ░▒░▒░▒░    "
        ],
        # Frame 2
        [
            "        ▲        ",
            "       ╱█╲       ",
            "      ╱███╲      ",
            "     │█████│     ",
            "     │█▓▓▓█│     ",
            "     │█▒▒▒█│     ",
            "     │█░░░█│     ",
            "    ╱███████╲    ",
            "   ╱█████████╲   ",
            "  ││ ▓▓▓▓▓ ││  ",
            "  ││ ▒▒▒▒▒ ││  ",
            "   ╲╲     ╱╱   ",
            "    ╲╲═══╱╱    ",
            "     ╲═══╱     ",
            "    ▒▒▓▒▒▓▒▒    ",
            "    ░▒░▒░▒░    ",
            "     ░·░·░     "
        ],
        # Frame 3
        [
            "        ▲        ",
            "       ╱█╲       ",
            "      ╱███╲      ",
            "     │█████│     ",
            "     │█▓▓▓█│     ",
            "     │█▒▒▒█│     ",
            "     │█░░░█│     ",
            "    ╱███████╲    ",
            "   ╱█████████╲   ",
            "  ││ ▓▓▓▓▓ ││  ",
            "  ││ ▒▒▒▒▒ ││  ",
            "   ╲╲     ╱╱   ",
            "    ╲╲═══╱╱    ",
            "     ╲═══╱     ",
            "    ░▒░▒░▒░    ",
            "     ░·░·░     ",
            "      ·..·      "
        ]
    ]
    
    # Fire/explosion frames - Enhanced with debris and shockwaves
    explosion_frames = [
        # Frame 1 - Initial impact with debris
        [
            "          ░▒▓▓▒░          ",
            "       *░▒▓███▓▒░*       ",
            "     *·▒▓████████▓▒·*     ",
            "      ·▓████████▓·      ",
            "     ░▒▓██████▓▒░  *   ",
            "    ·  ░▒▓▓▓▒░     ·    ",
            "  *                  *  "
        ],
        # Frame 2 - Expanding fireball
        [
            "      * ░▒▓▓▓▓▓▓▓▒░ *     ",
            "   ·░▒▓████████▓▒░·   ",
            "  *▒▓█████████████▓▒*  ",
            "  ·▓█████████████▓·  ",
            "   ▒▓█████████████▓▒   ",
            "  * ░▒▓████████▓▒░ *  ",
            "     ·░▒▓▓▓▓▓▓▓▒░·     ",
            "  *  ·    ·    ·  *  "
        ],
        # Frame 3 - Peak explosion with flying debris
        [
            "  · ░▒▓▓▓▓▓▓▓▓▓▓▒░ ·  ",
            " *░▒▓████████████▓▒░* ",
            "· ▒▓█████████████████▓▒ ·",
            " ·▓███████████████▓· ",
            "*·▓███████████████▓·*",
            "· ▒▓█████████████████▓▒ ·",
            " *░▒▓████████████▓▒░* ",
            "  · ░▒▓▓▓▓▓▓▓▓▓▓▒░ ·  ",
            " *  ·    ☼    ·  * "
        ],
        # Frame 4 - Spreading with shockwave
        [
            "  · ░▒▓▓▓▓▓▓▓▓▓▓▓▒░ ·  ",
            "* ░▒▓████████████████▓▒░ *",
            "·▒▓███████████████████▓▒·",
            " ▓█████████████████▓ ",
            " ▓█████████████████▓ ",
            "·▒▓███████████████████▓▒·",
            "* ░▒▓████████████████▓▒░ *",
            "  · ░▒▓▓▓▓▓▓▓▓▓▓▓▒░ ·  ",
            "~·~·~·~·~·~·~·~·~·~·~·~",
            "  ·    ☼    ☼    ·  "
        ],
        # Frame 5 - Large spreading fireball
        [
            " · ░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒░ · ",
            "*░▒▓████████████████▓▒░*",
            "·▒▓█████████████████████▓▒·",
            " ▒▓███████████████████▓▒ ",
            " ·▓█████████████████▓· ",
            "  ▒▓███████████████▓▒  ",
            " * ░▒▓███████████▓▒░ * ",
            "    ·░▒▓▓▓▓▓▓▓▒░·    ",
            "~≈~≈~≈~≈~≈~≈~≈~≈~≈~≈~≈",
            " ☼    ·    ·    ☼ "
        ],
        # Frame 6 - Dissipating with smoke
        [
            "  · ░▒▓▓▓▓▓▓▓▓▓▓▓▒░ ·  ",
            " *░▒▓████████████▓▒░* ",
            "  ·▒▓█████████████▓▒·  ",
            "   ░▓███████████▓░   ",
            "    ▒▓█████████▓▒    ",
            "   · ░▒▓▓▓▓▓▓▓▒░ ·   ",
            "      ░▒▓▓▓▒░      ",
            " ≈~≈~≈~≈~≈~≈~≈~≈~≈ ",
            "   ☼    ·    ☼   "
        ]
    ]
    
    # ASCII title
    title_lines = [
        "████████╗██╗  ██╗███████╗    ███╗   ██╗███████╗██╗  ██╗████████╗",
        "╚══██╔══╝██║  ██║██╔════╝    ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝",
        "   ██║   ███████║█████╗      ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ",
        "   ██║   ██╔══██║██╔══╝      ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ",
        "   ██║   ██║  ██║███████╗    ██║ ╚████║███████╗██╔╝ ██╗   ██║   ",
        "   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ",
        "                                                                  ",
        "       ██████╗ ███████╗███╗   ██╗     █████╗ ██╗",
        "      ██╔════╝ ██╔════╝████╗  ██║    ██╔══██╗██║",
        "      ██║  ███╗█████╗  ██╔██╗ ██║    ███████║██║",
        "      ██║   ██║██╔══╝  ██║╚██╗██║    ██╔══██║██║",
        "      ╚██████╔╝███████╗██║ ╚████║    ██║  ██║██║",
        "       ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝",
        "                                                  ",
        "      ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ███████╗",
        "      ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝",
        "      ███████║███████║██║     █████╔╝ █████╗  ██████╔╝███████╗",
        "      ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗╚════██║",
        "      ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║███████║",
        "      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝"
    ]
    
    screen_width = 80
    
    # Phase 1: Rocket descending with acceleration
    for drop_position in range(-17, 12):
        sys.stdout.write("\033[H")  # Move to top
        
        output = []
        
        # Add empty lines before rocket
        for _ in range(max(0, drop_position)):
            output.append("")
        
        # Draw rocket if still visible
        if drop_position < 10:
            frame_idx = drop_position % len(rocket_frames)
            
            # Color shifts as it descends (cooling effect)
            if drop_position < 0:
                rocket_color = CYAN
            elif drop_position < 3:
                rocket_color = WHITE
            elif drop_position < 6:
                rocket_color = GOLD
            else:
                rocket_color = BRIGHT_RED if drop_position % 2 == 0 else ORANGE
            
            for line in rocket_frames[frame_idx]:
                centered_line = line.center(screen_width)
                output.append(f"{rocket_color}{centered_line}{RESET}")
            
            # Enhanced trailing fire with multiple lines
            if drop_position > -5:
                # Intensity increases as it descends
                intensity = min(drop_position + 5, 8)
                
                for trail_line in range(min(intensity, 5)):
                    if trail_line == 0:
                        trail = "▓▓█▓▓█▓▓" if drop_position % 2 == 0 else "▒▒▓▒▒▓▒▒"
                        trail_color = BRIGHT_RED
                    elif trail_line == 1:
                        trail = "▒▒▓▒▒▓▒▒" if drop_position % 2 == 0 else "░▒░▒░▒░"
                        trail_color = ORANGE
                    elif trail_line == 2:
                        trail = "░▒░▒░▒░" if drop_position % 3 == 0 else "·░·░·░·"
                        trail_color = GOLD
                    else:
                        trail = "·░·░·" if drop_position % 2 == 0 else "··..··"
                        trail_color = YELLOW
                    
                    output.append(f"{trail_color}{trail.center(screen_width)}{RESET}")
                
                # Add speed particles
                if drop_position > 3:
                    particles = "* · * · *" if drop_position % 2 == 0 else "· * · * ·"
                    output.append(f"{GOLD}{particles.center(screen_width)}{RESET}")
        
        for line in output:
            sys.stdout.write(line + "\n")
        
        sys.stdout.flush()
        
        # Accelerating descent
        if drop_position < 0:
            time.sleep(0.10)
        elif drop_position < 5:
            time.sleep(0.07)
        else:
            time.sleep(0.05)
    
    # Phase 2: Enhanced explosion sequence with multi-color layers
    for exp_idx, explosion in enumerate(explosion_frames):
        sys.stdout.write("\033[H")
        
        output = []
        
        # Add spacing
        for _ in range(6):
            output.append("")
        
        # Draw explosion with multi-layer coloring
        for line_idx, line in enumerate(explosion):
            colored_line = ""
            for char_idx, char in enumerate(line):
                if char == '█':
                    # Hottest core
                    if exp_idx < 2:
                        colored_line += f"{WHITE}{char}{RESET}"
                    else:
                        colored_line += f"{BRIGHT_RED}{char}{RESET}"
                elif char == '▓':
                    # Hot layer
                    colored_line += f"{BRIGHT_RED}{char}{RESET}"
                elif char == '▒':
                    # Medium heat
                    colored_line += f"{ORANGE}{char}{RESET}"
                elif char == '░':
                    # Outer flame
                    colored_line += f"{GOLD}{char}{RESET}"
                elif char == '*':
                    # Flying debris
                    debris_colors = [GOLD, YELLOW, WHITE]
                    colored_line += f"{debris_colors[(exp_idx + char_idx) % len(debris_colors)]}{char}{RESET}"
                elif char == '·':
                    # Smaller debris
                    colored_line += f"{YELLOW}{char}{RESET}"
                elif char == '☼':
                    # Bright sparks
                    colored_line += f"{WHITE}{char}{RESET}"
                elif char in ['~', '≈']:
                    # Shockwave
                    wave_color = CYAN if exp_idx % 2 == 0 else MATRIX_GREEN
                    colored_line += f"{wave_color}{char}{RESET}"
                else:
                    colored_line += char
            
            centered_line = colored_line.center(screen_width)
            output.append(centered_line)
        
        # Add expanding shockwave ring
        if exp_idx >= 2:
            ring_width = 10 + exp_idx * 8
            shockwave = "═" * ring_width
            shock_color = CYAN if exp_idx % 2 == 0 else WHITE
            output.append(f"{shock_color}{shockwave.center(screen_width)}{RESET}")
            
            # Add debris field
            debris_line = ""
            for d in range(8):
                debris_chars = ["*", "·", "◦", "•"]
                debris_colors = [WHITE, GOLD, YELLOW, ORANGE]
                debris_line += f"{debris_colors[(exp_idx + d) % len(debris_colors)]}{debris_chars[(exp_idx + d) % len(debris_chars)]}{RESET}  "
            output.append(debris_line.center(screen_width))
        
        for line in output:
            sys.stdout.write(line + "\n")
        
        sys.stdout.flush()
        time.sleep(0.13)
    
    # Phase 3: Title emerges dramatically from fire
    chars_revealed = 0
    total_chars = sum(len(line) for line in title_lines)
    
    for reveal_step in range(25):
        sys.stdout.write("\033[H")
        
        # Calculate chars to reveal with acceleration
        if reveal_step < 10:
            chars_revealed = reveal_step * (total_chars // 25)
        else:
            chars_revealed = min(total_chars, 10 * (total_chars // 25) + (reveal_step - 10) * (total_chars // 12))
        
        output = []
        
        # Residual fire with smoke transition
        if reveal_step < 15:
            fire_intensity = max(1, 15 - reveal_step)
            
            # Top fire layer
            if reveal_step < 8:
                fire_line = "▓▒░" * fire_intensity
                fire_color = BRIGHT_RED if reveal_step % 3 == 0 else ORANGE if reveal_step % 3 == 1 else GOLD
                output.append(f"{fire_color}{fire_line.center(screen_width)}{RESET}")
            
            # Smoke layer
            smoke_line = "▒░·" * (fire_intensity // 2 + 1)
            smoke_color = GOLD if reveal_step % 2 == 0 else YELLOW
            output.append(f"{smoke_color}{smoke_line.center(screen_width)}{RESET}")
            output.append("")
        else:
            output.append("")
            output.append("")
        
        # Progressive title reveal with burning effect
        char_count = 0
        for line_idx, line in enumerate(title_lines):
            revealed_line = ""
            for char_idx, char in enumerate(line):
                if char_count < chars_revealed:
                    color = gradient[line_idx % len(gradient)]
                    
                    # Burning edges effect
                    if char != " " and char_count >= chars_revealed - 15:
                        if reveal_step % 3 == 0:
                            burn_color = BRIGHT_RED if char_count % 2 == 0 else ORANGE
                            revealed_line += f"{burn_color}{char}{RESET}"
                        elif reveal_step % 3 == 1:
                            burn_color = ORANGE if char_count % 2 == 0 else GOLD
                            revealed_line += f"{burn_color}{char}{RESET}"
                        else:
                            revealed_line += f"{color}{char}{RESET}"
                    else:
                        revealed_line += f"{color}{char}{RESET}"
                elif char_count < chars_revealed + 10:
                    # Forming zone - show heat haze
                    if char != " " and reveal_step > 3:
                        haze_chars = ["░", "▒", "·"]
                        haze_colors = [ORANGE, GOLD, YELLOW]
                        haze_idx = (reveal_step + char_idx) % len(haze_chars)
                        revealed_line += f"{haze_colors[haze_idx]}{haze_chars[haze_idx]}{RESET}"
                    else:
                        revealed_line += " "
                else:
                    # Future zone - show faint smoke
                    if char != " " and reveal_step > 8:
                        revealed_line += f"{WHITE}·{RESET}"
                    else:
                        revealed_line += " "
                char_count += 1
            
            centered_line = revealed_line.center(screen_width)
            output.append(centered_line)
        
        # Dynamic fire particles and embers at bottom
        if chars_revealed < total_chars:
            # Main fire line
            fire_particles = ""
            for p in range(8):
                p_chars = ["▓", "▒", "░", "·", "*", "◦"]
                p_colors = [BRIGHT_RED, ORANGE, GOLD, YELLOW]
                p_idx = (reveal_step + p) % len(p_chars)
                fire_particles += f"{p_colors[p % len(p_colors)]}{p_chars[p_idx]}{RESET} "
            output.append(fire_particles.center(screen_width))
            
            # Floating embers
            if reveal_step > 5:
                embers = ""
                for e in range(5):
                    if (reveal_step + e) % 3 == 0:
                        embers += f"{BRIGHT_RED}*{RESET}   "
                    elif (reveal_step + e) % 3 == 1:
                        embers += f"{ORANGE}·{RESET}   "
                    else:
                        embers += f"{GOLD}◦{RESET}   "
                output.append(embers.center(screen_width))
        
        for line in output:
            sys.stdout.write(line + "\n")
        
        sys.stdout.flush()
        time.sleep(0.10)
    
    # Phase 4: Final display with dramatic pulsing and glowing aura
    for pulse in range(8):
        sys.stdout.write("\033[H")
        
        output = []
        
        # Heat wave at top
        if pulse < 4:
            heat_line = "~≈~≈~" * (4 - pulse)
            heat_color = ORANGE if pulse % 2 == 0 else GOLD
            output.append(f"{heat_color}{heat_line.center(screen_width)}{RESET}")
        
        output.append("")
        
        # Pulsing colors with intensity variation
        pulse_sequence = [BRIGHT_RED, ORANGE, GOLD, YELLOW, GOLD, ORANGE, BRIGHT_RED, ORANGE]
        base_pulse_color = pulse_sequence[pulse % len(pulse_sequence)]
        
        for line_idx, line in enumerate(title_lines):
            colored_line = ""
            
            # Apply wave effect character by character for smooth transitions
            for char_idx, char in enumerate(line):
                if char == " ":
                    colored_line += char
                else:
                    # Determine color based on wave position
                    wave_position = (line_idx + pulse) % 5
                    
                    if wave_position == 0:
                        color = BRIGHT_RED
                    elif wave_position == 1:
                        color = ORANGE
                    elif wave_position == 2:
                        color = GOLD
                    elif wave_position == 3:
                        color = YELLOW
                    else:
                        color = gradient[line_idx % len(gradient)]
                    
                    # Add glow effect on certain characters
                    if pulse < 4 and char_idx % 10 == pulse:
                        colored_line += f"{WHITE}{char}{RESET}"
                    else:
                        colored_line += f"{color}{char}{RESET}"
            
            centered_line = colored_line.center(screen_width)
            output.append(centered_line)
        
        # Multi-layer ember and spark effects
        output.append("")
        
        # Top ember layer - floating up
        ember_layer1 = ""
        for e in range(10):
            if (pulse + e) % 4 == 0:
                ember_layer1 += f"{BRIGHT_RED}✦{RESET} "
            elif (pulse + e) % 4 == 1:
                ember_layer1 += f"{ORANGE}*{RESET} "
            elif (pulse + e) % 4 == 2:
                ember_layer1 += f"{GOLD}◦{RESET} "
            else:
                ember_layer1 += f"{YELLOW}·{RESET} "
        output.append(ember_layer1.center(screen_width))
        
        # Bottom ember layer - rising
        ember_layer2 = ""
        for e in range(8):
            offset = (pulse + e + 2) % 5
            if offset == 0:
                ember_layer2 += f"{ORANGE}✧{RESET}  "
            elif offset == 1:
                ember_layer2 += f"{GOLD}*{RESET}  "
            elif offset == 2:
                ember_layer2 += f"{YELLOW}◦{RESET}  "
            else:
                ember_layer2 += f"{BRIGHT_RED}·{RESET}  "
        output.append(ember_layer2.center(screen_width))
        
        # Ground glow
        if pulse % 2 == 0:
            glow = "▓▒░" * 8
            glow_color = ORANGE if pulse % 4 == 0 else GOLD
            output.append(f"{glow_color}{glow.center(screen_width)}{RESET}")
        
        for line in output:
            sys.stdout.write(line + "\n")
        
        sys.stdout.flush()
        time.sleep(0.18)
    
    print("\n")

# Clear screen
print("\033[2J\033[H", end="")

# Check which animation should play
if selected_banner_type == "planet":
    animate_planet_banner()
elif selected_banner_type == "van":
    animate_van_banner()
elif selected_banner_type == "rocket":
    animate_rocket_banner()
else:
    # Animate main banner - reveal line by line
    for i, line in enumerate(lines):
        color = gradient[i]
        # Streaming reveal
        for j in range(len(line) + 1):
            print(f"\033[{i+1};1H{color}{line[:j]}{RESET}", end="", flush=True)
            time.sleep(0.001)  # Fast reveal

    # Move cursor down
    print("\n" * 1)

# Animate subtitle

# Modern subtitle (static, clean)


import sys


def center_text(text, width=80):
    return text.center(width)

def ascii_glow(text, width=80, times=8, delay=0.09):
    """ASCII glow and underline animation for MASTER CHANDARA"""
    glow_chars = ["░", "▒", "▓", "█"]
    colors = [WHITE, GOLD, BRIGHT_RED, ORANGE]
    # Glow effect
    for i in range(times):
        char = glow_chars[i % len(glow_chars)]
        color = colors[i % len(colors)]
        glow_line = center_text(char * (len(text) + 8), width)
        sys.stdout.write(f"{color}{glow_line}{RESET}\r")
        sys.stdout.flush()
        time.sleep(delay/3)
        sys.stdout.write(f"{RESET}\r")
        sys.stdout.flush()
        time.sleep(delay/3)
    # Main text
    sys.stdout.write(f"{GOLD}{center_text(text, width)}{RESET}\n")
    sys.stdout.flush()
    # Underline animation
    underline = "=" * len(text)
    for i in range(len(underline)+1):
        sys.stdout.write(f"{ORANGE}{center_text(underline[:i], width)}{RESET}\r")
        sys.stdout.flush()
        time.sleep(0.006)
    sys.stdout.write(f"{ORANGE}{center_text(underline, width)}{RESET}\n")
    sys.stdout.flush()

def fade_in(text, color=RESET, steps=6, delay=0.04, width=80):
    """Fade-in effect for subtitle lines, centered"""
    # Simulate fade by increasing brightness (using color codes)
    color_steps = [WHITE, CYAN, GOLD, ORANGE, BRIGHT_RED, color]
    for s in range(steps):
        sys.stdout.write(f"{color_steps[s % len(color_steps)]}{center_text(text, width)}{RESET}\r")
        sys.stdout.flush()
        time.sleep(delay/2)
    sys.stdout.write(f"{color}{center_text(text, width)}{RESET}\n")
    sys.stdout.flush()

def typewriter_effect(text, color=GOLD, delay=0.03, width=80):
    """Typewriter effect with cursor"""
    centered_start = (width - len(text)) // 2
    for i in range(len(text) + 1):
        cursor = "█" if i % 2 == 0 else "▌"
        line = " " * centered_start + text[:i] + cursor
        sys.stdout.write(f"\r{color}{line}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(f"\r{color}{' ' * centered_start}{text}{RESET}\n")
    sys.stdout.flush()

def matrix_rain_text(text, color=MATRIX_GREEN, width=80):
    """Matrix-style falling text reveal"""
    chars = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
    centered_text = text.center(width)
    for step in range(15):
        line = ""
        for i, char in enumerate(centered_text):
            if char == " ":
                line += " "
            elif step > i % 12:
                line += f"{color}{char}{RESET}"
            else:
                rand_char = random.choice(chars)
                line += f"{CYAN}{rand_char}{RESET}"
        sys.stdout.write(f"\r{line}")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"\r{color}{centered_text}{RESET}\n")
    sys.stdout.flush()

def glitch_text(text, color=BRIGHT_RED, iterations=8, width=80):
    """Glitch effect with random character replacement"""
    glitch_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~░▒▓█"
    centered_text = text.center(width)
    for _ in range(iterations):
        glitched = ""
        for char in centered_text:
            if char != " " and random.random() < 0.3:
                glitched += f"{BRIGHT_RED}{random.choice(glitch_chars)}{RESET}"
            else:
                glitched += f"{color}{char}{RESET}"
        sys.stdout.write(f"\r{glitched}")
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write(f"\r{color}{centered_text}{RESET}\n")
    sys.stdout.flush()

def pulse_text(text, colors=None, pulses=6, width=80):
    """Pulsing color effect"""
    if colors is None:
        colors = [DARK_RED, BRIGHT_RED, ORANGE, GOLD, YELLOW, WHITE]
    centered_text = text.center(width)
    for i in range(pulses):
        color = colors[i % len(colors)]
        sys.stdout.write(f"\r{color}{centered_text}{RESET}")
        sys.stdout.flush()
        time.sleep(0.12)
    sys.stdout.write(f"\r{colors[-1]}{centered_text}{RESET}\n")
    sys.stdout.flush()

def wave_text(text, color=CYAN, width=80):
    """Wave animation across text"""
    centered_text = text.center(width)
    wave_colors = [CYAN, MATRIX_GREEN, GOLD, ORANGE, BRIGHT_RED]
    for wave_pos in range(len(centered_text) + 5):
        line = ""
        for i, char in enumerate(centered_text):
            if char == " ":
                line += " "
            elif wave_pos - 3 <= i <= wave_pos + 3:
                wave_color = wave_colors[abs(i - wave_pos) % len(wave_colors)]
                line += f"{wave_color}{char}{RESET}"
            else:
                line += f"{color}{char}{RESET}"
        sys.stdout.write(f"\r{line}")
        sys.stdout.flush()
        time.sleep(0.02)
    sys.stdout.write(f"\r{color}{centered_text}{RESET}\n")
    sys.stdout.flush()

def show_subtitle_and_quote():
    """Show MASTER CHANDARA subtitle and random quote - called once"""
    ascii_glow("MASTER CHANDARA", width=80, times=12, delay=0.07)
    fade_in("⚡ Threat Intelligence ⚡", GOLD, steps=8, delay=0.03, width=80)
    sys.stdout.write("\n")
    fade_in("L8-VULN CONFIRMED › Human-Factor Exposure Spike", BRIGHT_RED, steps=8, delay=0.03, width=80)
    fade_in("Severity: CRITICAL · Vector: Social Engineering · S/N: High", ORANGE, steps=8, delay=0.03, width=80)
    fade_in("Telemetry: Synced · Analyst Controls: Active · Adversary: Persistent", CYAN, steps=8, delay=0.03, width=80)
    
    # --- Dynamic Quote Block ---
    quotes = [
    "Security is not a product, but a process.",
    "The quieter you become, the more you are able to hear.",
    "In the world of cyber, trust is earned, not given.",
    "Every wall is a door. — Emerson",
    "The best defense is a good offense.",
    "Code is poetry. Security is the rhyme.",
    "Adversaries never sleep. Neither do we.",
    "Intelligence is the ability to adapt to change. — Stephen Hawking",
    "Hack the planet, but secure your soul.",
    "The only secure system is one that is powered off, cast in a block of concrete, and sealed in a lead-lined room with armed guards. — Gene Spafford",
    "Mastery is not a destination, but a journey.",
    "Stay curious. Stay vigilant.",
    "The greatest glory in living lies not in never falling, but in rising every time we fall. — Nelson Mandela",
    "If you know the enemy and know yourself, you need not fear the result of a hundred battles. — Sun Tzu",
    "Innovation distinguishes between a leader and a follower. — Steve Jobs",
    "Measure twice, patch once.",
    "Amateurs hack systems, professionals hack people. — Kevin Mitnick",
    "Persistence and patience outlast every APT.",
    "There are two types of companies: those that have been hacked, and those that will be. — Robert Mueller",
    "In APT we trust… no one.",
    "The chain is only as strong as the weakest log.",
    "Move fast and secure things.",
    "Assume breach. Respond faster.",
    "Your crown jewels are someone's side quest.",
    "Threats evolve. So must you.",
    "Hunt evil. Sleep later.",
    "Zero trust isn't a product. It's a lifestyle.",
    "If you're not living on the edge, you're taking up too much space.",
    "Root is not a privilege, it's a lifestyle.",
    "I hacked your system before you finished your latte.",
    "Exploit early, exploit often.",
    "Your firewall is just a speed bump.",
    "Offense informs defense. Stay offensive.",
    "We don't rise to the level of our expectations; we fall to the level of our access.",
    "Pwn or be pwned.",
    "Nice opsec, bro. Said no red teamer ever.",
    "Why do red teamers prefer dark mode? Less light, more shadows to hide in.",
    "Blue team walks into a bar. Bartender says, 'Sorry, we don't serve your type.' Denies all traffic.",
    "How many SOC analysts does it take to change a lightbulb? None—they just alert on it for 6 months.",
    "My password is the last 8 digits of π. Red team still got in.",
    "We need better work-life balance, said no incident responder during a breach.",
    "DevOps motto: Ship it now, secure it never.",
    "CISO asked for a budget increase. CFO replied, 'Have you tried turning MFA off and on again?'",
    "The bug you find today stops the breach tomorrow.",
    "Every junior who reads one more logline becomes tomorrow's senior who saves the company.",
    "You don't need permission to hunt—only curiosity and a lab.",
    "Root starts with reading the manual no one else bothered to open.",
    "The adversary is already inside. Be the reason they regret it.",
    "Skills > certs. Ship exploits in your homelab before you ship résumés.",
    "Pwn young, patch forever.",
    "They laugh at your TryHackMe rank until you're the one detecting their APT.",
    "Your first 0day isn't in code—it's in persistence.",
    "Stay paranoid. Stay broke. Stay learning. One day you'll be dangerous.",
    "The SOC needs heroes. Start as the villain in your own lab.",
    "Future CISOs began as kids who ran nc -lvp 4444 just to see what happens.",
    "Why do programmers prefer dark mode? Light attracts bugs.",
    "There are 10 types of people: those who understand binary and those who don't.",
    "I told my wife I'm a 10/10 developer. She asked on which base.",
    "Real programmers set the exit code to 1 before the program even runs.",
    "Why do Java devs wear glasses? They don't C#.",
    "A programmer walks into a bar. Orders 1 beer. Orders 0 beers. Orders 999999999 beers. Orders -1 beers. Orders a lizard. Bartender: 'Segmentation fault.'",
    "It works on my machine → career in offensive security confirmed.",
    "How to make a programmer leave the office? Promise there's Wi-Fi at home.",
    "90% of coding is Googling. The other 10% is copying without the minus signs.",
    "Senior dev motto: If it compiles, ship it. If it doesn't, blame the intern.",
    "AI doesn't replace hackers. It arms the curious.",
    "Train your model like you train your exploits: on chaos.",
    "Prompt injection is the new SQLi. Master it.",
    "Your LLM just became my C2. Thanks for the weights.",
    "Hallucinations are features when you're red-teaming.",
    "Fine-tune on darknet dumps, deploy on victim GPUs.",
    "Jailbreaking models > jailbreaking people.",
    "The next 0-day is a prompt, not a payload.",
    "If the model refuses, you just didn't speak adversarial enough.",
    "Steal the weights, keep the soul.",
    "In God we trust. All others bring training data.",
    "AI is the ultimate script kiddie with a PhD."
    ]
    selected_quote = random.choice(quotes)
    fade_in(f"\"{selected_quote}\"", MATRIX_GREEN, steps=10, delay=0.025, width=80)
    time.sleep(1)

def show_planet_subtitle():
    """Show cosmic-themed subtitle for planet banner - featuring Chandara"""
    sys.stdout.write("\n")
    
    # Cosmic title with typewriter
    typewriter_effect("◆ CHANDARA'S COSMIC TERMINAL ◆", CYAN, delay=0.04)
    
    # Wave animation subtitle
    wave_text("━━━ Navigating the Digital Universe ━━━", MATRIX_GREEN)
    
    sys.stdout.write("\n")
    
    # Fade in status lines
    fade_in("◉ Orbital Status: ONLINE", GOLD, steps=6, delay=0.02, width=80)
    fade_in("◉ Satellite Link: ENCRYPTED", CYAN, steps=6, delay=0.02, width=80)
    fade_in("◉ Commander: CHANDARA", BRIGHT_RED, steps=6, delay=0.02, width=80)
    
    sys.stdout.write("\n")
    
    # Space-themed quotes featuring Darkcoders
    space_quotes = [
    "The cosmos is within us. We are made of star-stuff. — Carl Sagan",
    "Darkcoder explores where no packet has gone before.",
    "In space, no one can hear your firewall scream. — Chandara",
    "The universe is under no obligation to make sense. Neither is my code.",
    "Houston, we have root access. — Chandara",
    "Stars are just distant servers waiting to be discovered.",
    "Chandara: Mapping the dark web of the cosmos.",
    "Every satellite is a potential pivot point. — Chandara",
    "The galaxy is Chandara's playground.",
    "Space: the final frontier for exploitation. — Chandara",
    "Orbit achieved. Payload deployed. — Chandara",
    "Darkcoder doesn't stargaze. Darkcoder star-hacks.",
    "The universe expands. So does Mr.Chandara's access.",
    "Cosmic rays are just nature's packet injection.",
    "Darkcoder: Because even aliens need cybersecurity.",
    "Why did the astronaut break up with his girlfriend? He needed space.",
    "I was going to tell you a joke about the weak nuclear force, but it didn't have enough pull.",
    "What do you call a star that is bad at coding? A supernova bug!",
    "My favorite planet is Jupiter. It's not just a gas giant, it's a *major* gas giant.",
    "The difference between a programmer and an astronomer? One looks at the stars, the other makes stars look like bugs.",
    "Darkcoder's favorite constellation is Orion, because it has the **Belt** for security.",
    "What's a hacker's favorite kind of galaxy? A **Milky Way** of credentials.",
    "Why don't you ever see Martians browsing the dark web? Because they already found the **Red Planet**.",
    "I tried to make a shirt out of gravity. It was super heavy, but it really held me down.",
    "Houston, we have a problem... and I think it's a **cross-site scripting** vulnerability.",
    "What's a coder's favorite coffee in space? **Decaf**-tation.",
    "Why did the black hole get an email from a Nigerian prince? Because it was the greatest **pull** scam in the universe.",
    "Chandara's biggest fear isn't space debris; it's getting caught in an **infinite loop** of light years.",
    "What's the best way to organize a space party? You **planet**!",
    "The Enterprise runs on Linux. They need to boldly go where no kernel panic has gone before.",
    "NASA's biggest threat isn't meteors, it's a **phishing attempt** disguised as a distress signal.",
    "Why did the sun skip college? Because it already had a million **degrees**.",
    "Black holes are proof that the universe can crash and needs to be **rebooted**.",
    "Chandara: The only person who knows the **admin password** to the asteroid belt.",
    "What do you call a malicious asteroid? A **spam-rock**.",
    "If Earth is the client, the Sun is a highly effective, but constantly overloaded, **web server**.",
    "Life is like a cosmic ray: fast, chaotic, and possibly corrupting your **bit-flip** memory.",
    "Darkcoder's favorite type of wormhole is one that bypasses the **proxy server**.",
    "Why was the space station having an argument? Because they had too much **space-tension**.",
    "Gravity is just the universe enforcing its **physical constraints**.",
    "What is Chandara's favorite key combination? $Ctrl+Alt+Del$-ete the space-time continuum.",
    "Astronauts are just highly paid users checking the **connection status**.",
    "I told my friend a joke about the Hubble Telescope, but it was a bit **far-fetched**.",
    "When a planet goes down, you have to check the **log-arhythms**.",
    "The only thing expanding faster than the universe is the **exploit database**.",
    "Why was the Mars Rover grumpy? Because it had a **bad case of the bluescreens**.",
    "The universe is written in C++. That's why everything is so hard to **debug**.",
    "An alien asked Chandara for the Wi-Fi password. Chandara replied, 'It's **123456... light years**.'",
    "What did Saturn say to Jupiter? 'I see you have a nice ring, but mine is **highly encrypted**.'",
    "Don't trust atoms. They make up **everything**, including those insecure packets.",
    "What do you call an astronaut's typo? A **cosmic error**.",
    "Chandara's biggest hack wasn't a bank; it was figuring out the universe's **seed value**.",
    "Why are there no bars on the moon? Because it takes too long to get there to get a **download**.",
    "The Earth is not flat. It's just a heavily loaded, **circular dependency**.",
    "The final frontier isn't space. It's properly implementing **zero-trust**.",
    "When Darkcoder retires, he plans to spend his days analyzing the **star-log** files.",
    "What do you call a lonely rocket? A **missile-ing** piece.",
    "The Big Crunch is just the universe finally running out of **memory allocation**.",
    "Chandara doesn't believe in parallel universes; only **forked repositories**.",
    "Why did the alien bring a ladder to the spaceship? To get to the **high-resolution** display."
  ]
    
    pulse_text(f"✧ \"{random.choice(space_quotes)}\" ✧", 
               [CYAN, MATRIX_GREEN, GOLD, WHITE, CYAN], pulses=8)
    time.sleep(0.5)

def show_van_subtitle():
    """Show road warrior themed subtitle for van banner - featuring Chandara"""
    sys.stdout.write("\n")
    
    # Glitch effect title
    glitch_text("▶▶▶ CHANDARA'S MOBILE OPS ◀◀◀", ORANGE, iterations=10)
    
    # Matrix rain subtitle
    matrix_rain_text("━━━ Rolling Thunder Security ━━━")
    
    sys.stdout.write("\n")
    
    # Status with pulse effects
    pulse_text("⚡ MOBILE UNIT: ACTIVE", [GOLD, ORANGE, BRIGHT_RED, GOLD], pulses=4)
    fade_in("⚡ ENCRYPTION: AES-256-CHANDARA", CYAN, steps=5, delay=0.02, width=80)
    fade_in("⚡ STEALTH MODE: ENGAGED", MATRIX_GREEN, steps=5, delay=0.02, width=80)
    
    sys.stdout.write("\n")
    
    # Road warrior quotes
    van_quotes = [
      "Darkcoder: Hacking on the highway, leaving no trace.",
      "The road is my office. The van is my fortress. — Darkcoder",
      "Rolling exploits, mobile mayhem. — Darkcoder",
      "No fixed address. Maximum attack surface.",
      "Darkcoder's van: Wardriving since before it was cool.",
      "Moving target. Persistent threat. — Chandara",
      "I don't need a data center. I AM the data center. — Chandara",
      "Darkcoder: Delivering 0-days door to door.",
      "The highway is just a really long ethernet cable.",
      "Chandara's motto: Hack fast, drive faster.",
      "Mobile pentesting: Because evil doesn't stay home.",
      "GPS says turn left. Chandara says pivot right.",
      "Fuel gauge: Low. Exploitation level: Maximum.",
      "Chandara: Making ISPs nervous since day one.",
      "The open road is the best VPN.",
      "My license plate is encrypted. — Chandara",
      "What do you call a hacker in a van? A **delivery mechanism**.",
      "Chandara doesn't stop for gas; he stops to **sniff Wi-Fi**.",
      "Traffic jam? Perfect time for a **man-in-the-middle attack** on the smart signals.",
      "This van runs on coffee and **backdoors**.",
      "The only thing Chandara leaves behind is a **compromised server**.",
      "Don't honk. I'm building a **botnet**.",
      "Van life means never having to clear your **browser cache** in the same spot.",
      "My van is stealthier than any **Tor exit node**.",
      "Chandara's idea of a scenic route is one with lots of **unsecured municipal networks**.",
      "The best way to escape a trace? Hit the **off-road switch**.",
      "Sleep is for the weak. Exploits are for the wide-awake.",
      "What's in the van? Just a couple of **custom air-gapped systems** and a sleeping bag.",
      "The dash cam is for security... and for logging the **APs I pass**.",
      "Chandara's van: Where the payload is always **mobile**.",
      "The van's firewall has a higher rating than its **bumper**.",
      "My Wi-Fi antenna is bigger than your **entire router stack**.",
      "Every stop sign is a reminder to check the **latest patches**.",
      "Chandara's coffee cup holder is also a **faraday cage** for sensitive drives.",
      "I prefer **road noise** to noisy data packets. — Chandara",
      "You call it a road trip. I call it a **network penetration sweep**.",
      "Why use a commercial VPN when you can just **drive across state lines**?",
      "The police car chasing me? Just a distraction for the **zero-day delivery**.",
      "This isn't a parking spot. It's a temporary **command and control** center.",
      "Chandara doesn't parallel park; he **lateral-moves** into a spot.",
      "The van is the payload; the destination is merely the **target's perimeter**.",
      "What’s Chandara’s favorite classic rock song? **'On the Road Again' (with an ARP scan)**.",
      "The only thing reliable in this van is the **Kali Linux** install.",
      "Check engine light? No, that's just the indicator for a successful **data exfiltration**.",
      "The best defense against surveillance is constant **kinetic motion**."
  ]
    
    typewriter_effect(f"» \"{random.choice(van_quotes)}\" «", BRIGHT_RED, delay=0.025)
    time.sleep(0.5)

def show_rocket_subtitle():
    """Show explosive/launch themed subtitle for rocket banner - featuring Chandara"""
    sys.stdout.write("\n")
    
    # Explosive pulse title
    pulse_text("◢◤◢◤ CHANDARA LAUNCH CONTROL ◢◤◢◤", 
               [DARK_RED, BRIGHT_RED, ORANGE, GOLD, YELLOW, WHITE], pulses=10)
    
    # Wave effect subtitle
    wave_text("━━━ Deploying Digital Payloads ━━━", ORANGE)
    
    sys.stdout.write("\n")
    
    # Launch status
    fade_in("▲ PAYLOAD: ARMED", BRIGHT_RED, steps=5, delay=0.02, width=80)
    fade_in("▲ TARGET: ACQUIRED", ORANGE, steps=5, delay=0.02, width=80)
    fade_in("▲ OPERATOR: CHANDARA", GOLD, steps=5, delay=0.02, width=80)
    
    # Countdown effect
    countdown = ["T-3...", "T-2...", "T-1...", "IGNITION!", "LIFTOFF!"]
    colors = [CYAN, GOLD, ORANGE, BRIGHT_RED, WHITE]
    for i, phase in enumerate(countdown):
        sys.stdout.write(f"\r{colors[i]}{phase.center(80)}{RESET}")
        sys.stdout.flush()
        time.sleep(0.3)
    sys.stdout.write("\n\n")
    
    # Explosive quotes
    rocket_quotes = [
        "Darkcoders: Launching exploits at escape velocity.",
        "Houston, the firewall has been breached. — Chandara",
        "Payload delivered. Target neutralized. — Chandara",
        "I don't crash systems. I make them land hard. — Chandara",
        "Darkcoder: Because some exploits need rocket fuel.",
        "Liftoff is just the beginning. Impact is the goal. — Chandara",
        "Not all who wander are lost. Some are just deploying payloads.",
        "Darkcoder: Making security teams sweat since ignition.",
        "The countdown to compromise starts now.",
        "Darkcoder doesn't knock. Let's blasts through.",
        "Every launch is a learning opportunity for defenders.",
        "Rockets are just very fast social engineering.",
        "Darkcoder: Achieving orbit around your defenses.",
        "Impact crater? That's just a new attack surface.",
        "Mission Control to Darkcoder: You are cleared for chaos."
    ]
    
    glitch_text(f"☢ \"{random.choice(rocket_quotes)}\" ☢", MATRIX_GREEN, iterations=6)
    time.sleep(0.5)

# Only show subtitle for static banner type (other animations have their own complete displays)
if selected_banner_type == "static":
    show_subtitle_and_quote()
elif selected_banner_type == "planet":
    show_planet_subtitle()
elif selected_banner_type == "van":
    show_van_subtitle()
elif selected_banner_type == "rocket":
    show_rocket_subtitle()
