package com.example.courseworkLuchnetskyi.dto;

import lombok.Data;

@Data
public class PlayerStatisticsDto {
    private Long playerId;
    private String playerName;
    private String teamName;
    private String position;
    private int matchesPlayed;
    private int goalsScored; 
}
