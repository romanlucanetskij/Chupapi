package com.example.courseworkLuchnetskyi.dto;

import java.time.LocalDate;
import lombok.Data;

@Data
public class MatchScheduleDto {
    private Long matchId;
    private String teamA;
    private String teamB;
    private LocalDate date;
}
