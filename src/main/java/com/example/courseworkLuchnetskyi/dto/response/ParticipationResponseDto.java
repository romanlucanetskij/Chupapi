package com.example.courseworkLuchnetskyi.dto.response;

public record ParticipationResponseDto(
    Long id,
    TeamResponseDto team,
    TournamentResponseDto tournament
) {}
