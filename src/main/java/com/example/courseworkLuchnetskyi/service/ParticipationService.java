package com.example.courseworkLuchnetskyi.service;

import com.example.courseworkLuchnetskyi.dto.request.ParticipationRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.ParticipationResponseDto;

import java.util.List;

public interface ParticipationService {
    ParticipationResponseDto addParticipation(ParticipationRequestDto dto);
    List<ParticipationResponseDto> getTeamsByTournament(Long tournamentId);
    List<ParticipationResponseDto> getTournamentsByTeam(Long teamId);
}
