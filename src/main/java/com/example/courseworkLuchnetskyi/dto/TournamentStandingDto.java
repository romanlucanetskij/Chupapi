package com.example.courseworkLuchnetskyi.dto;

import lombok.Data;

@Data
public class TournamentStandingDto {
    private String teamName;
    private int matchesPlayed;
    private int wins;
    private int draws;
    private int losses;
    private int goalsFor;
    private int goalsAgainst;
    private int goalDifference;
    private int points;
}
