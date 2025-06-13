package com.example.courseworkLuchnetskyi.dto.response;

import java.time.LocalDate;

public record MatchResponseDto(
    Long id,
    TournamentResponseDto tournament,
    TeamResponseDto teamA,
    TeamResponseDto teamB,
    LocalDate date,
    Integer scoreA,
    Integer scoreB
) {}
