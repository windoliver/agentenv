use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub color_enabled: bool,
}

impl Theme {
    pub fn color() -> Self {
        Self {
            color_enabled: true,
        }
    }

    pub fn mono() -> Self {
        Self {
            color_enabled: false,
        }
    }

    pub fn active_border(self) -> Style {
        if self.color_enabled {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn inactive_border(self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        }
    }

    pub fn header(self) -> Style {
        if self.color_enabled {
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn selected(self) -> Style {
        if self.color_enabled {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }
}
