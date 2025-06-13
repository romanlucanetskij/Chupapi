package com.example.courseworkLuchnetskyi.dto.request;

import java.time.LocalDate;

public record MatchRequestDto(
    Long tournamentId,
    Long teamAId,
    Long teamBId,
    LocalDate date,
    Integer scoreA,
    Integer scoreB
) {}
