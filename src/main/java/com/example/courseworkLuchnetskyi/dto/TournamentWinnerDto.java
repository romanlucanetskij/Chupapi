package com.example.courseworkLuchnetskyi.dto;

import lombok.Data;

@Data
public class TournamentWinnerDto {
    private Long tournamentId;
    private String tournamentName;
    private String winningTeamName;
}
