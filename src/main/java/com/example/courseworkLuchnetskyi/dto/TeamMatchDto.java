package com.example.courseworkLuchnetskyi.dto;

import java.time.LocalDate;
import lombok.Data;

@Data
public class TeamMatchDto {
    private Long matchId;
    private String opponent;
    private LocalDate date;
    private String tournamentName;
    private Integer scoreFor;
    private Integer scoreAgainst;
}
