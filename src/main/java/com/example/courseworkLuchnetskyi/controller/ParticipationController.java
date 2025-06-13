package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.dto.request.ParticipationRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.ParticipationResponseDto;
import com.example.courseworkLuchnetskyi.service.ParticipationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/api/participations")
@RequiredArgsConstructor
public class ParticipationController {

    private final ParticipationService participationService;

    @PostMapping
    public ResponseEntity<ParticipationResponseDto> addParticipation(@RequestBody @Valid ParticipationRequestDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(participationService.addParticipation(dto));
    }

    @GetMapping("/tournament/{tournamentId}")
    public ResponseEntity<List<ParticipationResponseDto>> getTeamsByTournament(@PathVariable Long tournamentId) {
        return ResponseEntity.ok(participationService.getTeamsByTournament(tournamentId));
    }

    @GetMapping("/team/{teamId}")
    public ResponseEntity<List<ParticipationResponseDto>> getTournamentsByTeam(@PathVariable Long teamId) {
        return ResponseEntity.ok(participationService.getTournamentsByTeam(teamId));
    }
}
